import { CheckCircle2, Crown, Sparkles, ArrowLeft, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

const plans = [
  {
    name: 'Starter',
    price: '$29/mo',
    perks: ['Single target workspace', 'Weekly scan cadence', 'Basic reporting export'],
  },
  {
    name: 'Pro',
    price: '$99/mo',
    perks: ['Multi-project coverage', 'Daily scan cadence', 'AI-prioritized remediation feed'],
    featured: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    perks: ['Unlimited targets', 'Dedicated onboarding', 'Custom policy and audit workflows'],
  },
];

export default function Subscription() {
  return (
    <div className="min-h-screen text-white px-4 py-8 md:px-8 md:py-10">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8 flex flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-center sm:gap-4">
          <Link
            to="/"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/20 px-3 py-2 transition-all hover:border-white/40 hover:bg-white/10 sm:justify-start"
          >
            <ArrowLeft size={16} />
            Back
          </Link>
          <Link
            to="/login"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-white px-4 py-2 font-semibold text-black transition-all hover:bg-gray-200"
          >
            Continue To Login
            <ArrowRight size={16} />
          </Link>
        </div>

        <section className="rounded-2xl border border-white/15 bg-white/[0.03] backdrop-blur-xl p-6 md:p-8">
          <p className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.15em] text-cyan-200/90">
            <Sparkles size={14} />
            Subscription Plans
          </p>
          <h1 className="text-3xl md:text-5xl font-semibold mt-3">Choose A SentinelAI Plan</h1>
          <p className="text-sm md:text-base text-gray-300 mt-3 max-w-3xl">
            Services access now routes through subscription onboarding. Select a plan that matches your security
            program, then continue to login and workspace setup.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-8">
            {plans.map((plan) => (
              <article
                key={plan.name}
                className={`rounded-xl border p-5 ${plan.featured ? 'border-cyan-300/70 bg-cyan-500/10' : 'border-white/20 bg-white/5'}`}
              >
                <p className="text-xs uppercase tracking-[0.12em] text-gray-300">{plan.name}</p>
                <p className="text-3xl font-semibold mt-2">{plan.price}</p>
                <ul className="mt-5 space-y-3 text-sm text-gray-100">
                  {plan.perks.map((perk) => (
                    <li key={perk} className="flex items-start gap-2">
                      <CheckCircle2 size={16} className="mt-0.5 text-cyan-300" />
                      <span>{perk}</span>
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 mt-8 pt-5 border-t border-white/10">
            <a
              href="mailto:sales@sentinelai.local?subject=SentinelAI%20Enterprise%20Subscription"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-white/20 hover:border-white/40 hover:bg-white/10 transition-all"
            >
              <Crown size={16} />
              Contact Sales
            </a>
            <Link
              to="/login"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-white text-black font-semibold hover:bg-gray-200 transition-all"
            >
              Proceed
              <ArrowRight size={16} />
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}