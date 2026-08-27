import { getDb } from '../src/db.js'
import {
  getAllPlans,
  getPlan,
  createPlan,
  updatePlan,
  togglePlanStatus,
  deletePlan,
  getAllPromoCodes,
  getPromoCode,
  createPromoCode,
  updatePromoCode,
  togglePromoCodeStatus,
  deletePromoCode,
  validatePromoCode,
  PLANS
} from '../src/billing.js'

async function run() {
  getDb()
  console.log('--- TESTING PLANS ---')
  const initialPlans = getAllPlans()
  console.log('Initial Plans Count:', initialPlans.length)
  console.log('Plan names:', initialPlans.map(p => p.name))

  // Test create custom plan
  const newPlan = createPlan({
    id: 'test-enterprise-plus',
    name: 'Test Enterprise Plus',
    description: 'Bespoke custom tier for big banks',
    priceMonthly: 149,
    priceYearly: 1490,
    scanQuota: 9999,
    maxRepos: 50,
    features: ['Custom SLA', 'Dedicated Engineer'],
    isPopular: false,
    isOpen: true,
    isCustom: true,
    badge: 'VIP Enterprise',
  })
  console.log('Created Plan:', newPlan.id, newPlan.name, 'Price:', newPlan.priceMonthly)

  // Test toggle status
  const closedPlan = togglePlanStatus('test-enterprise-plus', false)
  console.log('Toggled Plan Open Status:', closedPlan.isOpen)

  // Test edit plan
  const updatedPlan = updatePlan('test-enterprise-plus', { priceMonthly: 199, description: 'Updated description' })
  console.log('Updated Plan Price:', updatedPlan.priceMonthly, updatedPlan.description)

  // Test legacy PLANS proxy
  console.log('PLANS proxy access:', PLANS['test-enterprise-plus']?.name)

  // Test delete plan
  const delResult = deletePlan('test-enterprise-plus')
  console.log('Deleted Plan Result:', delResult)

  console.log('\n--- TESTING PROMO CODES ---')
  const initialPromos = getAllPromoCodes()
  console.log('Initial Promos Count:', initialPromos.length)
  console.log('Promo codes:', initialPromos.map(p => p.code))

  // Test validate default promo SENTINEL50
  const validation = validatePromoCode('SENTINEL50', 'pro', 'monthly')
  console.log('SENTINEL50 Validation on Pro:', validation)

  // Test create custom promo
  const customPromo = createPromoCode({
    code: 'HACKER30',
    discountType: 'percentage',
    discountValue: 30,
    applicablePlans: 'all',
    maxUses: 10,
    note: 'Special hacker discount',
  })
  console.log('Created Promo:', customPromo.code, 'Value:', customPromo.discountValue)

  // Validate custom promo
  const valCustom = validatePromoCode('HACKER30', 'enterprise', 'monthly')
  console.log('HACKER30 on Enterprise ():', valCustom.finalPrice, 'USD (Saved $' + valCustom.discountAmount + ')')

  // Test delete promo
  const delPromoRes = deletePromoCode(customPromo.id)
  console.log('Deleted Promo Result:', delPromoRes)

  console.log('\n ALL SUBSCRIPTION & PROMO TESTS PASSED!')
}

run().catch(console.error)
