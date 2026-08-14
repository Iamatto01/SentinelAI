// Quick functional test for the offensive pattern scanner.
// Run: node scripts/test-pattern-scan.js
import { UnifiedPipeline } from '../src/pipeline.js'

const inst = new UnifiedPipeline()

const files = [
  {
    path: 'app.js',
    content: [
      'const apiKey = "dummy_test_api_key_sample_123456789"',
      'const q = "SELECT * FROM users WHERE id=" + req.query.id',
      'const h = crypto.createHash("md5")',
      'eval(req.body.code)',
      'app.use(cors({ origin: "*" }))',
      'const tok = Math.random().toString(36)',
      'document.getElementById("x").innerHTML = req.query.name',
      'const q2 = db.query("SELECT * FROM orders WHERE user=" + req.params.id)',
      'const r = await fetch(req.body.url)',
      'Object.assign({}, req.body.data)',
      'console.log("user password:", password)',
      'app.get("/api/users/:id", (req, res) => { db.findById(req.params.id); })',
      'const jwtSecret = "secret123"',
      'require(req.query.module)',
      'const tpl = template.render(req.query.template)',
      'db.collection("users").find({ $where: req.body.query })',
      'res.send(req.query.name)',
    ].join('\n'),
  },
  {
    path: 'web.py',
    content: [
      'import pickle',
      'data = pickle.loads(request.data)',
      'aws_secret = "AWS_DUMMY_SECRET_KEY_EXAMPLE_0123"',
      'import yaml',
      'cfg = yaml.load(request.data)',
      'import xml.etree.ElementTree',
      'tree = xml.etree.ElementTree.parse(request.data)',
      'import urllib.request',
      'resp = urllib.request.urlopen(request.args.get("url"))',
      'import subprocess',
      'subprocess.call(request.args.get("cmd"), shell=True)',
      'import requests',
      'r = requests.get(request.args.get("url"))',
    ].join('\n'),
  },
  {
    path: 'old.php',
    content: [
      '<?php',
      '$r = mysql_query("SELECT * FROM u WHERE id=" . $_GET["id"]);',
      'echo shell_exec($_POST["cmd"]);',
      '$data = unserialize($_COOKIE["session"]);',
      'include $_GET["page"] . ".php";',
      'move_uploaded_file($_FILES["file"]["tmp_name"], "/uploads/" . $_FILES["file"]["name"]);',
      'echo $_GET["name"];',
      'header("Location: " . $_GET["redirect"]);',
    ].join('\n'),
  },
  {
    path: 'config.xml',
    content: [
      '<?xml version="1.0"?>',
      '<!DOCTYPE foo [',
      '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
      ']>',
      '<config>&xxe;</config>',
    ].join('\n'),
  },
  {
    path: 'uploadHelper.js',
    content: [
      'const multer = require("multer")',
      'const upload = multer({ dest: "uploads/" })',
      'app.post("/upload", upload.single("file"), (req, res) => {',
      '  // file saved without type check',
      '  res.json({ path: req.file.path })',
      '})',
      'const ALLOWED_EXT = [".php", ".exe", ".sh", ".jsp"]',
    ].join('\n'),
  },
]

const out = inst._patternScan(files)
console.log(`pattern-scan findings: ${out.length}`)
for (const f of out) console.log(` - ${f.severity.padEnd(8)} ${f.title}`)
if (!out.length) { console.error('EXPECTED FINDINGS — FAIL'); process.exit(1) }
console.log('PASS')
process.exit(0)
