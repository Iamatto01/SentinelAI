async function main() {
  const base = 'http://127.0.0.1:5000'
  const resPlans = await fetch(${base}/api/billing/plans).then(r => r.json())
  console.log('Public Plans:', resPlans.plans.length)

  const resPromo = await fetch(${base}/api/billing/validate-promo, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: 'SENTINEL50', planId: 'pro', billingInterval: 'monthly' })
  }).then(r => r.json())
  console.log('Validate Promo Result:', resPromo)

  const resLogin = await fetch(${base}/api/auth/login, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin@sentinelai.com', password: 'kali' })
  }).then(r => r.json())
  console.log('Admin Token:', resLogin.token ? 'YES' : 'NO')

  if (resLogin.token) {
    const adminPlans = await fetch(${base}/api/admin/plans, {
      headers: { 'Authorization': Bearer  }
    }).then(r => r.json())
    console.log('Admin Plans endpoint:', adminPlans.plans?.length)

    const adminPromos = await fetch(${base}/api/admin/promo-codes, {
      headers: { 'Authorization': Bearer  }
    }).then(r => r.json())
    console.log('Admin Promos endpoint:', adminPromos.promoCodes?.length)
  }
}

main().catch(console.error)
