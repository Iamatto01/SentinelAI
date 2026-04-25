import { useEffect } from 'react';
import { CheckCircle2, Crown, Sparkles } from 'lucide-react';
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
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    perks: ['Unlimited targets', 'Dedicated onboarding', 'Custom policy and audit workflows'],
  },
];

export default function SubscriptionModal({ open, onClose }) {
  useEffect(() => {
    if (!open) {
      return undefined;
    }

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [onClose, open]);

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div
        className="modal-content w-full max-w-4xl mx-4 rounded-2xl p-6 max-h-[92vh] overflow-y-auto"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.15em] text-cyan-200/90">
              <Sparkles size={14} />
              Subscription Required
            </p>
            <h3 className="text-2xl font-semibold mt-2">Choose A SentinelAI Plan To Continue</h3>
            <p className="text-sm text-gray-300 mt-2 max-w-2xl">
              Access to the Services console now opens with subscription onboarding. Pick the plan that fits your
              security program and continue to account setup.
            </p>
          </div>
          <button
            type="button"
            className="px-3 py-2 rounded-lg border border-white/20 hover:border-white/40 hover:bg-white/10 transition-all"
            onClick={onClose}
            aria-label="Close subscription popup"
          >
            Close
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          {plans.map((plan, idx) => (
            <article
              key={plan.name}
              className={`rounded-xl border p-4 ${idx === 1 ? 'border-cyan-300/60 bg-cyan-500/10' : 'border-white/15 bg-white/5'}`}
            >
              <p className="text-xs uppercase tracking-[0.12em] text-gray-300">{plan.name}</p>
              <p className="text-2xl font-semibold mt-2">{plan.price}</p>
              <ul className="mt-4 space-y-2 text-sm text-gray-200">
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

        <div className="flex flex-wrap items-center justify-between gap-3 mt-6 pt-4 border-t border-white/10">
          <button
            type="button"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-white/20 hover:border-white/40 hover:bg-white/10 transition-all"
            onClick={onClose}
          >
            Maybe Later
          </button>
          <div className="flex items-center gap-3">
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
              onClick={onClose}
            >
              Continue To Login
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}