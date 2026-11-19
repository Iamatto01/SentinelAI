/**
 * Report output contract — evidence validation, classification, aggregation.
 *
 * A report must not present unproven scanner chatter at the same weight as a
 * reproduced bug, and it must not print the same warning 40 times. This layer
 * answers three questions per finding before any page is rendered:
 *   1. Is there an actual artifact (tool output, HTTP response, payload echo)?
 *   2. Did anything settle the claim, and in which direction?
 *   3. Which findings are just the same root cause seen at N endpoints?
 *
 * Deliberately dependency-free so it can be unit-tested without pdfkit.
 *
 * NOTE on `exploitHint`: the PoC generator always fills `pocPayload`, so its
 * presence proves nothing. Only a hint that did not originate from that
 * template counts as a real artifact.
 */

import { coverageFromMeta } from './integrations/coverage.js'

export const VERIFY_STATUS = {  CONFIRMED: 'Confirmed',
  UNVERIFIED: 'Unverified',
  REJECTED: 'Rejected',
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** Evidence keys that are pipeline bookkeeping, not proof of the claim. */
export const NON_ARTIFACT_EVIDENCE_KEYS = new Set([
  'actions', 'exploitPlaybooks', 'aiEvidenceTier', 'validationTier',
  'out_of_scope',
  // Both spellings are live: the pipeline writes `version_unverified` in one
  // path and `versionUnverified` in another. Matching only one let the other
  // read as a capture.
  'version_unverified', 'versionUnverified',
  'sources', 'references', 'knownCves',
  // Pipeline bookkeeping written after verification. Recording "we asked a model
  // and it could not decide" must never be read back as evidence of the bug.
  'verification', 'aiUndecided', 'aiReasoning', 'aiAgent', 'aiConfidence',
  // A model's yes/no is a verdict, not a capture. If a finding ever nests it
  // inside `evidence`, reading it as an artifact field would let a bare
  // assertion promote itself to Confirmed — exactly the /cpanel defect.
  'aiVerification', 'isTruePositive', 'evidenceTier',
  // The exploit we intended to send is not a record of what came back. The PoC
  // generator always fills these, so counting them let every templated finding
  // self-confirm — a finding with nothing but `pocSource: 'template'` was being
  // read as "artifact observed".
  'pocSource', 'pocPayload', 'payload', 'attackCommand', 'pocSteps', 'steps',
  'exploitSteps', 'verificationCommand', 'concreteVerification', 'explanation',
  // Labels and explanations the pipeline writes *about* the claim. These are the
  // worst offenders because the more honestly a finding is marked unproven, the
  // more of these it carries — so `classification: 'discovery-only'` and an
  // `unconfirmedReason` explaining the missing artifact were certifying the
  // finding as "artifact-observed". A field describing the claim can never be
  // proof of it.
  'classification', 'unconfirmedReason', 'discoveryOnly',
  // The detector narrating itself: which routine ran, what it keyed off, and
  // which bucket the product was filed under. `kind: 'cms'` and
  // `detectionSource: 'live-http-response'` describe how the finding was
  // produced, not what the target returned.
  'kind', 'detectionSource', 'reason',
  // Probe bookkeeping: the hosts we compared against, the URLs we queued, and
  // the name of the detection routine that ran. All locators, no captures.
  'primaryHost', 'findingHost', 'scannedUrls', 'detection',
  // The dedup key built during ingestion (`cwe-1004|||cookie without httponly|
  // 127.0.0.1`). It identifies the finding; it is not something the target said.
  // The renderer already strips it before printing the evidence dump.
  'fingerprint',
])

/**
 * PoC keys that record where the payload came from, not what the target did.
 *
 * `extractArtifact` tests the BARE key inside the `poc` store and only prefixes
 * `poc.` afterwards, so the top-level `pocSource` exclusion above never applied
 * to a nested `poc: { source: 'PayloadsAllTheThings', retrieval: 'fts5' }`. The
 * result was that every finding carrying a knowledge-base lookup — which is
 * nearly all of them, whether or not anything was captured — read as
 * "artifact observed" in the executive summary.
 */
export const POC_BOOKKEEPING_KEYS = new Set([
  'source', 'retrieval', 'matchedCategories',
])

/** Keys that make a serialised object recognisably the finding's own record. */
const FINDING_ECHO_KEYS = ['title', 'severity', 'description', 'cweId', 'owaspCategory']

/**
 * `raw` is written by the ingestion layer as `cleanText(evidence)` — the very
 * same string it also stores as `description` (see `extractFindingsFromOutput`
 * in pipeline.js). When a producer serialised the finding record into `raw`,
 * the JSON that comes back is the finding's own columns echoed at us, which can
 * never confirm the finding. Because it is stored as a *string*, the
 * `isPrimitiveArtifact` type test accepts it, so 718 of 796 findings in the live
 * database were certifying themselves with it and the "no artifact" disclosure
 * became unreachable.
 *
 * The renderer already refuses these — `describeCapturedProof` and
 * `buildProofPanel` in report.js both test this exact shape, with the comment
 * "only strings that came off the wire". This is that rule, not a new
 * heuristic: across all 718 stored values the regex and a plain "is it JSON at
 * all" test agree exactly (718 hits each, zero disagreements), so nothing is
 * gained or lost by matching the renderer byte for byte.
 */
export function looksLikeFindingEcho(val) {
  if (typeof val === 'string') {
    return /^\{[\s\S]*"(title|severity|description|cweId|owaspCategory)"\s*:/.test(val.trim())
  }
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    return Object.keys(val).some((k) => FINDING_ECHO_KEYS.includes(k))
  }
  return false
}

function isFindingEcho(key, val) {
  if (key !== 'raw') return false
  return looksLikeFindingEcho(val)
}

/**
 * The nuclei JSONL branch stored the whole template wrapper as the finding's
 * `description` and `evidence.raw`, so those values are mid-JSON truncations of
 * that blob, not prose. Across all 956 stored descriptions this matches 22 rows
 * and every one of them begins `{"template`, so the precision is identical to a
 * plain "starts with a brace" test while remaining specific to the shape that
 * caused the defect. A wrapper longer than the 400-char description clip loses
 * its interior keys, which is why `looksLikeFindingEcho` only catches 9 of them.
 */
export function looksLikeTemplateWrapper(val) {
  if (typeof val === 'string') {
    return /^\{[\s\S]*"template(-id|-url|-path)?"\s*:/.test(val.trim())
  }
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    return typeof val.template === 'string' || typeof val.templateID === 'string'
  }
  return false
}

/**
 * Keys that only locate the probe. "HSTS header missing at /admin" with nothing
 * but `url: '/admin'` recorded proves only that we asked — not what came back.
 * Anything the target actually returned (status, body, headers, banner, output)
 * stays an artifact.
 */
export const LOCATION_EVIDENCE_KEYS = new Set([
  'url', 'path', 'endpoint', 'asset', 'parameter', 'param', 'field',
])

const isEvidenceField = (k) => !NON_ARTIFACT_EVIDENCE_KEYS.has(k)
  && !LOCATION_EVIDENCE_KEYS.has(k)
  && !ASSESSMENT_PROSE_KEYS.has(String(k).toLowerCase())

/**
 * Keys that record what the target actually EMITTED over the wire, as opposed to
 * a location, a flag, or the tool's own bookkeeping. A finding holding one of
 * these has a live capture and its claim can be re-checked by anyone; a finding
 * holding only `url`/`path` merely says where the scanner looked.
 *
 * This distinction is load-bearing. `needs-validation` used to blanket-demote
 * everything it was stamped on — including findings that had photographed the
 * target's response — because the stamp carried no notion of whether a capture
 * existed. The database shows the cost: 707 findings with a real capture filed
 * as unproven. The stamp must not be able to overrule a capture it cannot see.
 *
 * Membership rule: the key must name something the TARGET emitted. Keys that
 * are excluded on purpose, each for a demonstrated reason:
 *   - `payload` / `pocPayload` / `pocSource` — the exploit we intended to send.
 *     The PoC generator fills these on every templated finding, so counting them
 *     re-creates the self-confirmation defect documented on
 *     NON_ARTIFACT_EVIDENCE_KEYS: a finding with nothing but `pocSource:
 *     'template'` read as "artifact observed". Verified by reproduction.
 *   - `requestBody` / `requestHeaders` — what WE sent, not what came back.
 *   - `evidence` / `proof` / `artifact` — self-describing labels. A field named
 *     "evidence" holding an assertion is still an assertion; whoever names a key
 *     this way controls the classification.
 *   - `location` — a redirect target also reads as a place the scanner looked;
 *     `redirect` already covers the response-side signal.
 *   - `missing` / `present` / `matches` / `lines` / `matchedAt` — probe
 *     bookkeeping about the comparison, not a response.
 */
export const CAPTURE_EVIDENCE_KEYS = new Set([
  'body', 'responseBody', 'httpResponse', 'response', 'raw', 'output', 'stdout',
  'stderr', 'headers', 'responseHeaders', 'status',
  'statusCode', 'banner', 'snippet', 'extract',
  'setCookie',
  'cookie', 'tls', 'certificate', 'cert', 'dns', 'ports', 'openPorts',
  'content', 'html', 'text', 'sample',
  'responseTime', 'redirect', 'server', 'poweredBy', 'xPoweredBy',
])

export function safeEvidence(v) {
  let ev = v?.evidence
  if (typeof ev === 'string') {
    try { ev = JSON.parse(ev) } catch { ev = {} }
  }
  return ev && typeof ev === 'object' ? ev : {}
}

/**
 * A finding that claims a file, admin panel, endpoint, or resource exists or was
 * exposed is refuted if the captured HTTP response status is 404 (Not Found) or
 * 410 (Gone). Such findings must never be graded as confirmed or appear on fix
 * cards — the server explicitly told us the resource does not exist.
 *
 * The only exception is when the finding is specifically about detailed error
 * page leaks or custom 404 disclosure (e.g. stack traces inside a 404 response).
 */
export function isStatus404Refutation(v) {
  const ev = safeEvidence(v)
  const status = Number(ev.status ?? ev.statusCode ?? ev.httpStatus ?? ev.reverified?.status)
  if (status !== 404 && status !== 410) return false

  const text = `${v?.title || ''} ${v?.name || ''} ${v?.description || ''}`
  if (/error\s*page|stack\s*trace|verbose\s*error|404\s*(?:disclosure|leak|banner)/i.test(text)) {
    return false
  }
  return true
}

/**
 * A capture is a key we recognise AND a value the target produced. Booleans are
 * excluded because a flag records an assertion, never a response.
 */
export function findCaptures(v) {
  if (isStatus404Refutation(v)) return []
  const ev = safeEvidence(v)
  const keys = []
  for (const [k, val] of Object.entries(ev)) {
    if (!CAPTURE_EVIDENCE_KEYS.has(k)) continue
    // `raw` holds the script's own emitted JSON finding (`{"title":"Possible
    // webshell: /1.php","severity":"critical"}`), i.e. the scanner restating its
    // claim — not bytes the target returned. extractArtifact already refuses it
    // via isFindingEcho; capture detection must agree, or a finding's own
    // assertion becomes the proof of itself. That disagreement is what graded 25
    // phantom webshell findings `artifact-observed` / Confirmed.
    if (isFindingEcho(k, val)) continue
    // A flag records an assertion; never a response.
    if (typeof val === 'boolean') continue
    if (val == null) continue
    if (typeof val === 'string') {
      if (!val.trim()) continue
    } else if (typeof val === 'number') {
      if (!Number.isFinite(val)) continue
    } else if (Array.isArray(val)) {
      if (!val.length) continue
    } else if (typeof val === 'object') {
      if (!Object.keys(val).length) continue
    } else {
      continue
    }
    keys.push(k)
  }
  return keys
}


function isMeaningful(val) {
  if (val == null || val === '') return false
  if (Array.isArray(val)) return val.length > 0
  if (typeof val === 'object') return Object.keys(val).length > 0
  return true
}

/** An evidence value only counts if it is something the target emitted. */
function isPrimitiveArtifact(val) {
  if (typeof val === 'string') return val.trim() !== ''
  if (typeof val === 'number') return Number.isFinite(val)
  if (typeof val === 'boolean') return false // a flag is bookkeeping, never a capture
  return isMeaningful(val)
}

/**
 * Evidence keys that name the SCANNER, not the target.
 *
 * `evidence.tool: "nuclei"` is provenance — it records which binary produced the
 * record. Counting it as an artifact observation graded "Nginx End-of-Life -
 * Detect" as `artifact-observed` / Confirmed on a single field whose entire
 * content was the string "nuclei", and that grade is what exempted it from the
 * severity cap. The same hole would mark any tool-attributed finding verified.
 *
 * Deliberately narrow: only keys whose value is definitionally scanner-side.
 * A target-emitted `Server` header or `version` string must stay admissible.
 */
const SCANNER_BOOKKEEPING_KEYS = new Set([
  'tool', 'scanner', 'source', 'engine', 'template', 'templateid', 'templatename',
  'nuclei', 'module', 'agent', 'action', 'validationtier', 'aievidenceTier',
])

/**
 * Content keys that hold the SCANNER'S ASSESSMENT of a response rather than the
 * response itself.
 *
 * `extractArtifact` is a deny-list (`isEvidenceField`), so it accepts any key it
 * has not been told to reject. That default let a one-word prose assessment
 * certify a finding: `{ detail: 'nope' }` graded `artifact-observed`, and every
 * custom-script emission carries `detail` holding the script's own sentence
 * ("Possible webshell found at /1.php"). The value is authored by the detector,
 * which is the definition of a self-assertion.
 *
 * Confirmed captures have their own positive allow-list (`CAPTURE_EVIDENCE_KEYS`)
 * which never contained `detail`, and the report's evidence dump already
 * de-emphasises these fields — so excluding them here aligns grading with what
 * the rest of the contract already believed.
 *
 * Deliberately NOT extended to `description`/`notes`: those may legitimately
 * quote a server banner. `detail` is the field the heuristics actually exploit.
 */
const ASSESSMENT_PROSE_KEYS = new Set([
  'detail', 'details', 'message', 'msg', 'summary', 'assessment', 'verdict',
  'observation', 'observations', 'comment', 'remarks',
])

export function extractArtifact(v) {
  const ev = v.evidence && typeof v.evidence === 'object' ? v.evidence : {}
  const found = []
  for (const [k, val] of Object.entries(ev)) {
    if (!isEvidenceField(k)) continue
    if (isFindingEcho(k, val)) continue
    if (SCANNER_BOOKKEEPING_KEYS.has(String(k).toLowerCase())) continue
    if (!isPrimitiveArtifact(val)) continue
    found.push(k)
  }
  const poc = v.poc && typeof v.poc === 'object' ? v.poc : {}
  for (const [k, val] of Object.entries(poc)) {
    if (!isEvidenceField(k)) continue
    // The bare key is tested here; `poc.` is only prefixed onto the result.
    if (POC_BOOKKEEPING_KEYS.has(k)) continue
    if (!isPrimitiveArtifact(val)) continue
    found.push(`poc.${k}`)
  }
  // Exploit playbooks were matched from the registry during ingestion — an
  // attacker-relevant confirmation, but not a record of what the target did.
  const playbooks = Array.isArray(ev.exploitPlaybooks) ? ev.exploitPlaybooks.length : 0
  const hasModelVerdict = typeof v.aiVerification === 'boolean'
  // `pocSource` is stored alongside the PoC, not necessarily on the finding.
  const pocStore = v.poc && typeof v.poc === 'object' ? v.poc : {}
  const source = v.pocSource || pocStore.pocSource || null
  const hint = source && source !== 'template' ? source : null
  // Where the probe ran, reported separately so a bare "missing header" lead
  // can still tell the reader which endpoint to revisit.
  const location = ev.url || ev.path || ev.endpoint || v.asset || null
  return { fields: found, hasArtifact: found.length > 0, playbooks, hasModelVerdict, hint, location }
}

/**
 * Classify one finding. `verifyStatus` drives which section of the report it
 * appears in; `evidenceGrade` is how strong the supporting artifact is.
 */
export function classifyFinding(v) {
  const artifact = extractArtifact(v)
  if (isStatus404Refutation(v)) {
    return {
      ...v,
      evidenceFields: artifact.fields,
      evidenceGrade: 'none',
      verifyStatus: VERIFY_STATUS.REJECTED,
      evidenceLocation: artifact.location,
      captureFields: [],
    }
  }
  const tier = String(v.aiEvidenceTier || v.validationTier || '').toLowerCase()
  const conf = normalizeConfidence(v.aiConfidence)
  const captures = findCaptures(v)

  // `needs-validation` is the pipeline's explicit "exploitability is NOT proven"
  // marker, not a weak confirmation. The AI engine writes it for every rejection,
  // for every undecided heuristic ("no exploitability claim is made"), for a
  // version-fingerprint gap, and for the directory-hit reclassification whose
  // entire point is that no SQL artifact was ever observed. Treating it as a
  // confirmation made the caveat itself the proof: the finding rendered as
  // "Confirmed / artifact-observed" because `classification` and
  // `unconfirmedReason` — bookkeeping describing the claim — counted as captured
  // artifacts. That let a discovery-only lead reach the executive summary and the
  // attack chain as a verified vulnerability.
  //
  // It cannot, however, overrule a live capture. The stamp is prose-derived: the
  // heuristic's own "no artifact settles this claim" fallback, matched by regex
  // in the pipeline, downgrades findings that DID photograph the target's
  // response — 707 of them in the production database. A caveat about evidence
  // must yield to the evidence itself, so the unproven tier only applies when no
  // response was actually captured. Where a capture exists the finding is graded
  // `artifact-observed` and stays a confirmation with its raw response attached,
  // which is strictly more honest than hiding it: the operator can re-check it.
  const tierUnproven = tier === 'needs-validation' && captures.length === 0 && !artifact.hasArtifact

  let status
  if (v.aiVerification === false && captures.length === 0) {
    // Exploit-relevant rejections with high model confidence are dropped
    // outright; low-confidence rejections stay visible as leads because the
    // model may simply have lacked context. A rejection that contradicts a live
    // capture is not a rejection — the scanner saw the response; the model saw
    // prose — so it is demoted to a lead rather than deleted.
    status = conf >= 0.6 ? VERIFY_STATUS.REJECTED : VERIFY_STATUS.UNVERIFIED
  } else if (v.aiVerification === true) {
    status = VERIFY_STATUS.CONFIRMED
  } else if (captures.length > 0) {
    // A captured response is self-evidencing: it is re-checkable without the
    // model, which is precisely the standard a finding must meet.
    status = VERIFY_STATUS.CONFIRMED
  } else if (artifact.hasArtifact && !tierUnproven) {
    // No model verdict, but the scanner captured something concrete — and no
    // stage of the pipeline has recorded the claim as still unproven.
    status = VERIFY_STATUS.CONFIRMED
  } else {
    status = VERIFY_STATUS.UNVERIFIED
  }

  // A "confirmed" claim must rest on something the tool saw. A model assertion
  // is not evidence, and a registry playbook match proves the bug class is
  // exploitable in general — not that this target is. Both stay leads.
  const strongTier = tier === 'exploited' || tier === 'validated'
  if (status === VERIFY_STATUS.CONFIRMED && !artifact.hasArtifact && !strongTier && captures.length === 0) {
    status = VERIFY_STATUS.UNVERIFIED
  }

  // Confidence gate: a claim the verifier itself did not believe is a lead, not
  // a result. The `needs-validation` ceiling already caps what such a finding can
  // be rated; this decides where it is *filed*, because a capped `High` in the
  // findings table still reads as a vulnerability to anyone who never opens the
  // appendix. Below 70% the report's own numbers disprove the placement, so the
  // finding moves to Appendix A and says so.
  //
  // Escapes are the ones that represent contact with the target: only findings
  // with neither a capture nor `strongTier` are displaced, so `configuration-validated`
  // and `exploitation-proven` evidence is never hidden, and a model verdict of
  // `true` is not overruled by its own confidence number.
  const lowConfidenceLead = conf > 0 && conf < 0.7
    && captures.length === 0
    && !artifact.hasArtifact
    && !strongTier
    && v.aiVerification !== true
  if (lowConfidenceLead && status === VERIFY_STATUS.CONFIRMED) {
    status = VERIFY_STATUS.UNVERIFIED
  }

  let grade = 'none'
  if (tier === 'exploited') grade = 'exploitation-proven'
  else if (tier === 'validated') grade = 'configuration-validated'
  else if (captures.length > 0) grade = 'artifact-observed'
  else if (artifact.hasArtifact) grade = 'artifact-observed'
  else if (artifact.playbooks > 0) grade = 'playbook-only'
  else if (artifact.hasModelVerdict) grade = 'model-assertion-only'

  return {
    ...v,
    evidenceFields: artifact.fields,
    evidenceGrade: grade,
    verifyStatus: status,
    evidenceLocation: artifact.location,
    captureFields: captures,
    ...(lowConfidenceLead && status === VERIFY_STATUS.UNVERIFIED
      ? {
        unverifiedReason: `Verifier confidence ${Math.round(conf * 100)}% is below the 70% threshold and no response artifact backs the claim, so it is filed as an unverified lead.`,
        lowConfidenceLead: true,
      }
      : {}),
  }
}

/**
 * Confidence arrives on either a 0-1 or a 0-100 scale depending on the caller
 * (the PDF view layer divides by 100, stored agent verdicts keep percent).
 * Normalise so the rejection threshold means the same thing everywhere; without
 * this, every percent-scale rejection clears the bar and the "unconfident
 * rejection stays a lead" branch can never fire.
 */
export function normalizeConfidence(val) {
  const n = Number(val)
  if (!Number.isFinite(n) || n <= 0) return 0
  return n > 1 ? n / 100 : n
}

/**
 * A finding may not outrank its own evidence.
 *
 * `classifyFinding` decides which *section* a claim belongs in; this decides what
 * number is printed next to it. They were independent, so a claim could be filed
 * as an unverified lead in Appendix A and still render as `High · CVSS 8.6` in
 * the finding table and the executive summary — the reader saw the severity, not
 * the appendix, and the report read exactly like a scanner that found something.
 *
 * The rule is the one the whole contract rests on: severity is a statement about
 * exploitability, exploitability is established by an artifact, so no artifact
 * means no High. A lead stays visible — a 200 on `/shell.php` is worth an
 * analyst's time — it just cannot shout.
 *
 * Deliberately narrow, so it does not flatten real findings:
 *   • only `high`/`critical` are touched; medium and below already pass through;
 *   • only grades that represent NO observation of the target are capped —
 *     `none` (nothing at all), `playbook-only` (a registry match proving the bug
 *     class is exploitable in general) and `model-assertion-only` (a verdict with
 *     no response behind it). None of these is evidence that THIS target is
 *     exploitable, and treating them as "work that was actually done" is how 25
 *     phantom webshell findings kept a High rating while carrying nothing but a
 *     playbook. `artifact-observed`, `configuration-validated` and
 *     `exploitation-proven` are left alone — each rests on something captured;
 *   • a model verdict of `true` at >= 70% confidence is honoured as a substitute
 *     for the artifact, because the verifier read the response;
 *   • an explicitly exploited/validated tier is never capped.
 *
 * Returns the same view object with `severity` (and `cvss`/`cvssVector`) adjusted,
 * plus `severityCappedFrom` so the renderer can show what was claimed.
 */
const UNCAPPED_GRADES = new Set(['artifact-observed', 'configuration-validated', 'exploitation-proven'])
export function enforceSeverityFloor(v) {
  const sev = String(v?.severity || '').toLowerCase()
  if (sev !== 'high' && sev !== 'critical') return v
  const grade = String(v?.evidenceGrade || 'none')
  const tier = String(v?.aiEvidenceTier || v?.validationTier || '').toLowerCase()
  if (tier === 'exploited' || tier === 'validated') return v
  if (UNCAPPED_GRADES.has(grade)) return v
  const conf = normalizeConfidence(v?.aiConfidence)
  if (v?.aiVerification === true && conf >= 0.7) return v

  return {
    ...v,
    severity: 'medium',
    cvss: null,
    cvssVector: null,
    severityCappedFrom: sev,
    severityCapReason: 'No response artifact, verified exploit, or confident model verdict backs this claim, so it cannot be rated above Medium.',
  }
}

/**
 * Choose the member whose recorded proof best represents the shared root cause.
 * A collapsed group renders exactly one evidence block, so that block must come
 * from the member that captured something — captured artifact first, validation
 * tier second, model confidence only as a tie-breaker.
 */
function pickWitness(members) {
  const tierScore = (v) => {
    const t = String(v.aiEvidenceTier || v.validationTier || '').toLowerCase()
    if (t === 'exploited') return 2
    if (t === 'validated') return 1
    return 0
  }
  let best = members[0]
  for (const m of members) {
    const bHas = extractArtifact(best).hasArtifact
    const mHas = extractArtifact(m).hasArtifact
    if (mHas !== bHas) {
      if (mHas) best = m
      continue
    }
    const tierDiff = tierScore(m) - tierScore(best)
    if (tierDiff !== 0) {
      if (tierDiff > 0) best = m
      continue
    }
    const scoreDiff = sortScore(m) - sortScore(best)
    if (scoreDiff !== 0) {
      if (scoreDiff > 0) best = m
      continue
    }
    if ((normalizeConfidence(m.aiConfidence)) > (normalizeConfidence(best.aiConfidence))) best = m
  }
  return best
}

/**
 * The concrete subject a finding names: paths, endpoints, dotted versions,
 * filenames, hostnames. These are the tokens the group key deliberately
 * erases, so they are what tells a correctly collapsed group from a wrongly
 * collapsed one.
 *
 * Paths are matched with their leading slash. A slug-only pattern would miss
 * `/swagger-ui` and `/api-docs` entirely — hyphens are not separators — which
 * is exactly the case where two endpoint discoveries must be told apart.
 */
export function subjectDiscriminators(title) {
  const s = String(title || '').toLowerCase().replace(/^\s*\d+\.\s*/, '')
  const out = new Set()
  for (const m of s.matchAll(/\/[a-z0-9_.~%-]+(?:\/[a-z0-9_.~%-]+)*/g)) out.add(m[0])
  for (const m of s.matchAll(/\b[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\b/g)) out.add(m[0])
  for (const m of s.matchAll(/\b\d+(?:\.\d+)+\b/g)) out.add(m[0])
  return out
}

/** The single path a finding names, for the collapsed row's location list. */
export function primarySubjectPath(title) {
  const s = String(title || '').replace(/^\s*\d+\.\s*/, '')
  const m = s.match(/\/[A-Za-z0-9_.~%-]+(?:\/[A-Za-z0-9_.~%-]+)*/)
  if (!m) return null
  // A version string is not a path. "X-Powered-By header exposed:
  // Express/4.21.2" matched `/4.21.2`, which then became the "location" of the
  // finding and was printed as `curl -sI /4.21.2`. A real path segment names
  // something; a purely numeric-dotted token does not.
  if (!/[a-z]/i.test(m[0])) return null
  return m[0]
}

/**
 * Two titles name the same subject when their concrete identifiers agree. A
 * title naming nothing concrete cannot contradict anything, so it always
 * matches — "Technology Stack Detected" is not evidence for a specific path.
 */
export function subjectMatches(aTitle, bTitle) {
  const a = subjectDiscriminators(aTitle)
  const b = subjectDiscriminators(bTitle)
  if (!a.size || !b.size) return true
  for (const t of a) if (!b.has(t)) return false
  for (const t of b) if (!a.has(t)) return false
  return true
}

/**
 * A collapsed group may only adopt a member's evidence when that member names
 * the same subject the group prints.
 *
 * `aggregateFindings` normalises every path to `<path>` in the group key, so
 * "API endpoint discovered: /swagger-ui", "…: /api/v1/admin" and every other
 * discovered path are correctly one root cause — endpoint discovery ran and
 * found N paths. But the group then printed the FIRST member's title above the
 * most-captured member's payload, so card #24 was titled `/api/v1/admin` and
 * carried `/swagger-ui`'s JSON as its proof. The report layer cannot see this
 * (the DB is clean) because it materialises here, during aggregation.
 *
 * The witness is therefore restricted to members whose subject matches the
 * group's title. Return null when nothing agrees, so the caller prints no
 * evidence rather than another finding's evidence.
 */
function pickSubjectConsistentWitness(g) {
  const wanted = subjectDiscriminators(g.title)
  if (!wanted.size) return pickWitness(g.members)
  const agreeing = g.members.filter((m) => {
    const have = subjectDiscriminators(m.title)
    for (const w of wanted) if (!have.has(w)) return false
    return true
  })
  return agreeing.length ? pickWitness(agreeing) : null
}

/**
 * Re-derive a collapsed group's public fields from its members. Inheriting a
 * member's `evidence` without also inheriting that member's artifact field list
 * would print "Confirmed" above an empty evidence box — so status and evidence
 * are always recomputed together, never patched independently.
 */
function reconcileGroup(g) {
  const witness = pickSubjectConsistentWitness(g) || pickWitness(g.members)
  // The group prints its own subject. When the witness captured evidence for a
  // different one, keep the status (a capture did happen for this root cause)
  // but surface the mismatch so the renderer can withhold the payload instead
  // of presenting another finding's proof.
  const witnessSubjectMismatch = witness && !subjectMatches(witness.title, g.title) ? witness.title : null
  g.evidenceSubjectMismatch = witnessSubjectMismatch
  g.evidence = witness.evidence
  g.poc = witness.poc
  g.pocSource = witness.pocSource
  g.evidenceFields = witness.evidenceFields || []
  g.evidenceGrade = witness.evidenceGrade || 'none'
  g.evidenceLocation = witness.evidenceLocation || witness.asset || null
  if (witness.aiConfidence != null) g.aiConfidence = witness.aiConfidence

  const statuses = new Set(g.members.map((m) => m.verifyStatus))
  if (statuses.has(VERIFY_STATUS.CONFIRMED)) g.verifyStatus = VERIFY_STATUS.CONFIRMED
  else if (statuses.has(VERIFY_STATUS.UNVERIFIED)) g.verifyStatus = VERIFY_STATUS.UNVERIFIED
  else g.verifyStatus = VERIFY_STATUS.REJECTED
}

function sortScore(v) {
  const cvss = Number(v.cvss)
  return Number.isFinite(cvss) && cvss > 0 ? cvss : 0
}

/**
 * Scan-completeness view for the report header.
 *
 * A report that was produced without an active injection engine cannot claim a
 * risk posture — it has not looked. This turns the stored coverage descriptor
 * into a render-ready object so page 1 can say so, and into `coverage_gaps[]`
 * so the renderer can enumerate untested classes without string-parsing prose.
 *
 * @param {string|object|null} stored  raw `scans.blackbox_meta` value
 * @returns {{ degraded: boolean, criticalGaps: string[], gaps: string[],
 *   covered: string[], untestedClasses: object[], summary: string|null,
 *   missingTools: string[] }}
 */
export function coverageView(stored) {
  const cov = coverageFromMeta(stored)
  if (!cov) {
    return { degraded: false, criticalGaps: [], gaps: [], covered: [], untestedClasses: [], summary: null, missingTools: [] }
  }
  // First tool listed for each untested class is the one whose absence is named.
  const missingTools = [...new Set((cov.untestedClasses || []).map((c) => (c.missingTools || [])[0]).filter(Boolean))]
  return {
    degraded: Boolean(cov.degraded),
    criticalGaps: cov.criticalGaps || [],
    gaps: cov.gaps || [],
    covered: cov.covered || [],
    untestedClasses: cov.untestedClasses || [],
    summary: cov.summary || null,
    missingTools,
  }
}

/**
 * Collapse repeated warnings into one entry with an occurrence count.
 * Grouping key is (category, module, normalized title). Severity is deliberately
 * NOT part of the key: the same root cause reported at medium on one endpoint and
 * high on another is still one problem, and the group is promoted to the strongest
 * severity it was seen with. Endpoint-specific suffixes are normalised away so
 * "Missing HSTS on /a" and "… on /b" collapse into a single row plus a location
 * list, which is what makes a 40-row header wall render as one entry.
 */
export function aggregateFindings(classified) {
  const groups = new Map()
  for (const v of classified) {
    const normTitle = String(v.title || '')
      .toLowerCase()
      .replace(/\b(?:https?:\/\/)?[\w.-]+\.[a-z]{2,}(?:\/[^\s]*)?/gi, '<target>')
      // Bare paths and query strings left after the domain pass ("/admin", "?id=1").
      .replace(/(?:^|\s)\/[\w.~%+-]*(?:\/[\w.~%+-]*)*(?=[\s:,;)]|$)/g, (m) => (m[0] === ' ' ? ' ' : '') + '<path>')
      .replace(/[0-9]+/g, '<n>')
      .replace(/\s+/g, ' ')
      .trim()
    const key = [v.category || 'uncategorized', v.module || '', normTitle].join('|')
    // The path is the useful location; the bare asset host is not. `asset` is
    // the same host for every row of a scan, so letting it win produced
    // "Observed at 25 locations (e.g. italeemc.iium.edu.my)" — a list of one
    // repeated value that hid which endpoints were actually found.
    const where = (v.evidence && (v.evidence.url || v.evidence.path)) || primarySubjectPath(v.title) || v.asset
    const existing = groups.get(key)
    if (existing) {
      existing.occurrences += 1
      if (where && !existing.locations.includes(where) && existing.locations.length < 20) existing.locations.push(where)
      existing.members.push(v)
      // Keep the strongest representation of the shared root cause.
      if (SEV_ORDER.indexOf(v.severity) < SEV_ORDER.indexOf(existing.severity)) existing.severity = v.severity
      reconcileGroup(existing)
    } else {
      groups.set(key, {
        ...v,
        groupKey: key,
        occurrences: 1,
        locations: where ? [where] : [],
        members: [v],
      })
    }
  }
  return [...groups.values()].sort((a, b) => {
    const ai = SEV_ORDER.indexOf(a.severity), bi = SEV_ORDER.indexOf(b.severity)
    if (ai !== bi) return ai - bi
    if (b.occurrences !== a.occurrences) return b.occurrences - a.occurrences
    return sortScore(b) - sortScore(a)
  })
}
