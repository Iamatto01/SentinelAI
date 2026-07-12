import { CheckCircle2, Crown, Sparkles, ArrowLeft, ArrowRight, CreditCard, Check, Shield, Zap, Building2, Lock, Mail, User } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useState } from 'react';

const plans = [
  {
    name: 'Starter',
    price: '$29',
    period: '/mo',
    icon: Shield,
    color: 'from-blue-500/20 to-cyan-500/20',
    borderActive: 'border-blue-400',
    iconColor: 'text-blue-400',
    perks: ['Single target workspace', 'Weekly scan cadence', 'Basic reporting export', 'Email support'],
  },
  {
    name: 'Pro',
    price: '$99',
    period: '/mo',
    icon: Zap,
    color: 'from-cyan-500/20 to-purple-500/20',
    borderActive: 'border-cyan-400',
    iconColor: 'text-cyan-400',
    badge: 'Most Popular',
    perks: ['Multi-project coverage', 'Daily scan cadence', 'AI-prioritized remediation feed', 'Priority support', 'API access'],
    featured: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    icon: Building2,
    color: 'from-purple-500/20 to-pink-500/20',
    borderActive: 'border-purple-400',
    iconColor: 'text-purple-400',
    perks: ['Unlimited targets', 'Dedicated onboarding', 'Custom policy and audit workflows', 'SSO & RBAC', '24/7 dedicated support'],
  },
];

export default function Subscription() {
  const [selectedPlan, setSelectedPlan] = useState('Pro');
  const [showPayment, setShowPayment] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  const [cardNumber, setCardNumber] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvc, setCvc] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const navigate = useNavigate();

  const formatCardNumber = (value) => {
    const v = value.replace(/\D/g, '').slice(0, 16);
    const parts = [];
    for (let i = 0; i < v.length; i += 4) parts.push(v.slice(i, i + 4));
    return parts.join(' ');
  };

  const formatExpiry = (value) => {
    const v = value.replace(/\D/g, '').slice(0, 4);
    if (v.length >= 3) return v.slice(0, 2) + '/' + v.slice(2);
    return v;
  };

  const handleProceed = () => {
    if (selectedPlan && selectedPlan !== 'Enterprise') {
      setShowPayment(true);
    }
  };

  const handlePaymentSubmit = (e) => {
    e.preventDefault();
    setIsProcessing(true);
    setTimeout(() => {
      setIsProcessing(false);
      setPaymentSuccess(true);
      setTimeout(() => navigate('/login'), 2500);
    }, 2000);
  };

  const activePlan = plans.find(p => p.name === selectedPlan);

  /* ─── Payment View ─── */
  if (showPayment) {
    return (
      <div className="min-h-screen text-white flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-lg">
          {paymentSuccess ? (
            <div className="rounded-3xl border border-slate-800 bg-slate-950/80 backdrop-blur-md p-10 text-center shadow-2xl">
              <div className="w-20 h-20 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center mx-auto mb-6">
                <Check size={40} className="text-green-400" />
              </div>
              <h2 className="text-3xl font-bold mb-3">Payment Successful!</h2>
              <p className="text-slate-400 text-lg mb-2">Welcome to SentinelAI <span className="text-cyan-400 font-semibold">{selectedPlan}</span></p>
              <p className="text-slate-500 text-sm">Redirecting to login...</p>
              <div className="mt-6 w-full h-1 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-green-500 rounded-full animate-[progress_2.5s_ease-in-out]" 
                  style={{ animation: 'progress 2.5s ease-in-out forwards' }} />
              </div>
            </div>
          ) : (
            <div className="rounded-3xl border border-slate-800 bg-slate-950/80 backdrop-blur-md shadow-2xl overflow-hidden">
              {/* Header */}
              <div className="relative p-8 pb-6 border-b border-slate-800/50">
                <div className={`absolute inset-0 bg-gradient-to-br ${activePlan?.color || ''} opacity-30 pointer-events-none`}></div>
                <button 
                  onClick={() => setShowPayment(false)}
                  className="relative z-10 mb-6 inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors text-sm"
                >
                  <ArrowLeft size={16} /> Back to plans
                </button>
                <div className="relative z-10">
                  <p className="text-sm uppercase tracking-wider text-slate-400 mb-1">Complete Subscription</p>
                  <h2 className="text-2xl font-bold">{selectedPlan} Plan</h2>
                  <div className="flex items-baseline gap-1 mt-3">
                    <span className="text-4xl font-bold text-cyan-400">{activePlan?.price}</span>
                    <span className="text-slate-400">{activePlan?.period}</span>
                  </div>
                </div>
              </div>

              {/* Form */}
              <form onSubmit={handlePaymentSubmit} className="p-8 space-y-5">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">Full Name</label>
                    <div className="relative">
                      <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
                      <input type="text" placeholder="John Doe" value={name} onChange={e => setName(e.target.value)}
                        className="w-full bg-slate-900/60 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">Email</label>
                    <div className="relative">
                      <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
                      <input type="email" placeholder="john@company.com" value={email} onChange={e => setEmail(e.target.value)}
                        className="w-full bg-slate-900/60 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">Card Number</label>
                  <div className="relative">
                    <CreditCard size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
                    <input type="text" placeholder="4242 4242 4242 4242" value={cardNumber}
                      onChange={e => setCardNumber(formatCardNumber(e.target.value))}
                      className="w-full bg-slate-900/60 border border-slate-700 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">Expiry</label>
                    <input type="text" placeholder="MM/YY" value={expiry}
                      onChange={e => setExpiry(formatExpiry(e.target.value))}
                      className="w-full bg-slate-900/60 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">CVC</label>
                    <input type="text" placeholder="123" value={cvc} maxLength={4}
                      onChange={e => setCvc(e.target.value.replace(/\D/g, ''))}
                      className="w-full bg-slate-900/60 border border-slate-700 rounded-xl py-3 px-4 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
                  </div>
                </div>

                <button type="submit" disabled={isProcessing}
                  className="w-full mt-2 flex items-center justify-center gap-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-bold py-4 text-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30"
                >
                  {isProcessing ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <Lock size={18} />
                      Pay {activePlan?.price}{activePlan?.period} & Subscribe
                    </>
                  )}
                </button>

                <p className="text-center text-xs text-slate-500 flex items-center justify-center gap-1.5">
                  <Lock size={12} /> Secured with 256-bit SSL encryption
                </p>
              </form>
            </div>
          )}
        </div>
      </div>
    );
  }

  /* ─── Plan Selection View ─── */
  return (
    <div className="min-h-screen text-white px-4 py-10 md:px-8 md:py-14">
      <div className="max-w-6xl mx-auto">
        {/* Nav */}
        <div className="mb-10 flex flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-center sm:gap-4">
          <Link to="/"
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-950/80 backdrop-blur-md px-4 py-2.5 text-sm transition-all hover:border-slate-600 hover:bg-slate-900 sm:justify-start"
          >
            <ArrowLeft size={16} /> Back
          </Link>
          <Link to="/login"
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 px-5 py-2.5 font-semibold text-white transition-all shadow-lg shadow-cyan-500/20"
          >
            Continue To Login <ArrowRight size={16} />
          </Link>
        </div>

        {/* Header */}
        <div className="text-center mb-12">
          <p className="inline-flex items-center gap-2 text-sm uppercase tracking-widest text-cyan-400 mb-4">
            <Sparkles size={16} /> Subscription Plans
          </p>
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-4">Choose Your Plan</h1>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Select the plan that best fits your security needs. Upgrade or downgrade at any time.
          </p>
        </div>

        {/* Plan Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {plans.map((plan) => {
            const PlanIcon = plan.icon;
            const isSelected = selectedPlan === plan.name;
            return (
              <div
                key={plan.name}
                onClick={() => setSelectedPlan(plan.name)}
                className={`group relative flex flex-col overflow-hidden rounded-3xl border bg-slate-950/80 backdrop-blur-md p-8 cursor-pointer shadow-2xl transition-all duration-300 ${
                  isSelected
                    ? `${plan.borderActive} scale-[1.03] shadow-[0_0_40px_rgba(34,211,238,0.1)]`
                    : 'border-slate-800 hover:border-slate-700 hover:scale-[1.01]'
                }`}
              >
                {/* Ambient glow */}
                <div className={`absolute inset-0 bg-gradient-to-br ${plan.color} opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none ${isSelected ? '!opacity-40' : ''}`}></div>
                <div className="absolute pointer-events-none inset-0 bg-black/20 group-hover:bg-black/0 transition-colors duration-500 [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]"></div>

                {/* Badge */}
                {plan.badge && (
                  <div className="absolute top-4 right-4 px-3 py-1 rounded-full bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-bold uppercase tracking-wider">
                    {plan.badge}
                  </div>
                )}

                {/* Selected check */}
                {isSelected && (
                  <div className="absolute top-4 left-4">
                    <div className="w-7 h-7 rounded-full bg-cyan-500 flex items-center justify-center">
                      <Check size={16} className="text-white" />
                    </div>
                  </div>
                )}

                {/* Icon */}
                <div className={`relative z-10 mb-6 w-14 h-14 rounded-2xl flex items-center justify-center border border-slate-700 bg-slate-900/50 ${plan.iconColor} transition-all duration-500 group-hover:-translate-y-1 group-hover:scale-110 ${isSelected ? '-translate-y-1 scale-110' : ''}`}>
                  <PlanIcon size={28} />
                </div>

                {/* Plan name */}
                <p className="relative z-10 text-sm uppercase tracking-widest text-slate-400 font-semibold mb-2">{plan.name}</p>

                {/* Price */}
                <div className="relative z-10 flex items-baseline gap-1 mb-6">
                  <span className="text-4xl font-bold text-white">{plan.price}</span>
                  {plan.period && <span className="text-slate-500 text-lg">{plan.period}</span>}
                </div>

                {/* Perks */}
                <ul className="relative z-10 space-y-3 flex-1">
                  {plan.perks.map((perk) => (
                    <li key={perk} className="flex items-start gap-3">
                      <CheckCircle2 size={18} className={`mt-0.5 shrink-0 ${isSelected ? 'text-cyan-400' : 'text-slate-600'} transition-colors`} />
                      <span className="text-sm text-slate-300">{perk}</span>
                    </li>
                  ))}
                </ul>

                {/* Select button */}
                <button
                  onClick={(e) => { e.stopPropagation(); setSelectedPlan(plan.name); }}
                  className={`relative z-10 mt-8 w-full py-3 rounded-xl font-semibold text-sm transition-all duration-300 ${
                    isSelected
                      ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/20'
                      : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700'
                  }`}
                >
                  {isSelected ? '✓ Selected' : 'Select Plan'}
                </button>
              </div>
            );
          })}
        </div>

        {/* Bottom Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 rounded-3xl border border-slate-800 bg-slate-950/80 backdrop-blur-md p-6 shadow-2xl">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${activePlan?.iconColor} bg-slate-800/50 border border-slate-700`}>
              {activePlan?.icon && <activePlan.icon size={20} />}
            </div>
            <div>
              <p className="text-sm text-slate-400">Selected plan</p>
              <p className="font-bold text-lg">{selectedPlan} — {activePlan?.price}{activePlan?.period}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 w-full sm:w-auto">
            <a href="mailto:sales@sentinelai.local?subject=SentinelAI%20Enterprise%20Subscription"
              className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl border border-slate-700 bg-slate-900/50 hover:bg-slate-800 text-slate-300 hover:text-white transition-all text-sm font-semibold flex-1 sm:flex-none"
            >
              <Crown size={16} /> Contact Sales
            </a>
            <button onClick={handleProceed}
              disabled={selectedPlan === 'Enterprise'}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-bold transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed flex-1 sm:flex-none"
            >
              Proceed to Checkout <ArrowRight size={16} />
            </button>
          </div>
        </div>
      </div>
      <style>{`
        @keyframes progress {
          from { width: 0%; }
          to { width: 100%; }
        }
      `}</style>
    </div>
  );
}