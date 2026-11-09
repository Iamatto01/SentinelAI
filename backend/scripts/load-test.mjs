import autocannon from 'autocannon'

const baseUrl = process.env.BASE_URL || 'http://127.0.0.1:5000'
const duration = Number(process.env.BENCHMARK_SECONDS || 10)
const token = process.env.BENCHMARK_TOKEN
const headers = token ? { authorization: `Bearer ${token}` } : {}

const routes = ['/api/health', '/api/scans', '/api/findings']

for (const path of routes) {
  console.log(`Benchmarking ${baseUrl}${path} for ${duration}s`)
  await new Promise((resolve, reject) => {
    autocannon({ url: `${baseUrl}${path}`, duration, connections: 10, headers }, (error, result) => {
      if (error) return reject(error)
      console.log(JSON.stringify({
        path,
        requestsPerSecond: result.requests.average,
        latencyMs: result.latency.average,
        errors: result.errors,
        timeouts: result.timeouts,
      }))
      resolve()
    })
  })
}
