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

export const VERIFY_STATUS = {
  CONFIRMED: 'Confirmed',
  UNVERIFIED: 'Unverified',
  REJECTED: 'Rejected',
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** Evidence keys that are pipeline bookkeeping, not proof of the claim. */
export const NON_ARTIFACT_EVIDENCE_KEYS = new Set([
  'actions', 'exploitPlaybooks', 'aiEvidenceTier', 'validationTier',
  'out_of_scope', 'version_unverified', 'sources', 'references', 'knownCves',
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
  // Probe bookkeeping: the hosts we compared against, the URLs we queued, and
  // the name of the detection routine that ran. All locators, no captures.
  'primaryHost', 'findingHost', 'scannedUrls', 'detection',
])

/**
 * Keys that only locate the probe. "HSTS header missing at /admin" with nothing
 * but `url: '/admin'` recorded proves only that we asked — not what came back.
 * Anything the target actually returned (status, body, headers, banner, output)
 * stays an artifact.
 */
export const LOCATION_EVIDENCE_KEYS = new Set([
  'url', 'path', 'endpoint', 'asset', 'parameter', 'param', 'field',
])

const isEvidenceField = (k) => !NON_ARTIFACT_EVIDENCE_KEYS.has(k) && !LOCATION_EVIDENCE_KEYS.has(k)

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

export function extractArtifact(v) {
  const ev = v.evidence && typeof v.evidence === 'object' ? v.evidence : {}
  const found = []
  for (const [k, val] of Object.entries(ev)) {
    if (!isEvidenceField(k)) continue
    if (!isPrimitiveArtifact(val)) continue
    found.push(k)
  }
  const poc = v.poc && typeof v.poc === 'object' ? v.poc : {}
  for (const [k, val] of Object.entries(poc)) {
    if (!isEvidenceField(k)) continue
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
  const tier = String(v.aiEvidenceTier || v.validationTier || '').toLowerCase()
  const conf = normalizeConfidence(v.aiConfidence)

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
  const tierUnproven = tier === 'needs-validation'

  let status
  if (v.aiVerification === false) {
    // Exploit-relevant rejections with high model confidence are dropped
    // outright; low-confidence rejections stay visible as leads because the
    // model may simply have lacked context.
    status = conf >= 0.6 ? VERIFY_STATUS.REJECTED : VERIFY_STATUS.UNVERIFIED
  } else if (v.aiVerification === true) {
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
  if (status === VERIFY_STATUS.CONFIRMED && !artifact.hasArtifact && !strongTier) {
    status = VERIFY_STATUS.UNVERIFIED
  }

  let grade = 'none'
  if (tier === 'exploited') grade = 'exploitation-proven'
  else if (tier === 'validated') grade = 'configuration-validated'
  else if (artifact.hasArtifact) grade = 'artifact-observed'
  else if (artifact.playbooks > 0) grade = 'playbook-only'
  else if (artifact.hasModelVerdict) grade = 'model-assertion-only'

  return { ...v, evidenceFields: artifact.fields, evidenceGrade: grade, verifyStatus: status, evidenceLocation: artifact.location }
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
  return m ? m[0] : null
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
