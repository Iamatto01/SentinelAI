import { useCallback, useRef } from 'react';
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from 'framer-motion';
import { Link } from 'react-router-dom';
import Canvas3D from '../components/Canvas3D';
import {
  ArrowRight,
  Bot,
  Radar,
  ShieldAlert,
  FileText,
  Sparkles,
  CheckCircle2,
  Server,
} from 'lucide-react';
import './Home.css';

const featureCards = [
  {
    icon: Bot,
    title: 'Autonomous Security Agents',
    description:
      'Crew-based AI agents continuously map attack surfaces, trigger scans, and adapt strategy to your infrastructure changes.',
  },
  {
    icon: Radar,
    title: 'Continuous Multi-Tool Scanning',
    description:
      'SentinelAI orchestrates scanner pipelines for web, network, and API layers so visibility stays fresh, not stale.',
  },
  {
    icon: ShieldAlert,
    title: 'Risk-First Vulnerability Triage',
    description:
      'Findings are prioritized by exploitability and business impact so teams fix what matters first.',
  },
  {
    icon: FileText,
    title: 'Client Portal And Reporting',
    description:
      'Give stakeholders clean dashboards, status tracking, and exportable reports without exposing internal complexity.',
  },
];

const workflow = [
  {
    step: '01',
    title: 'Discover',
    text: 'AI agents inventory domains, hosts, endpoints, and shadow assets.',
  },
  {
    step: '02',
    title: 'Assess',
    text: 'Automated scan chains run with context-aware templates and timing.',
  },
  {
    step: '03',
    title: 'Correlate',
    text: 'Raw scanner outputs are normalized and deduplicated into clear risks.',
  },
  {
    step: '04',
    title: 'Act',
    text: 'Teams track remediation in one place with audit-ready evidence.',
  },
];

export default function Home() {
  const rootRef = useRef(null);
  const reducedMotion = useReducedMotion();

  const pointerX = useMotionValue(0);
  const pointerY = useMotionValue(0);
  const smoothPointerX = useSpring(pointerX, { stiffness: 85, damping: 22, mass: 0.35 });
  const smoothPointerY = useSpring(pointerY, { stiffness: 85, damping: 22, mass: 0.35 });

  const { scrollYProgress } = useScroll({
    target: rootRef,
    offset: ['start start', 'end end'],
  });

  const spotlightX = useTransform(smoothPointerX, [-1, 1], ['38%', '62%']);
  const spotlightY = useTransform(smoothPointerY, [-1, 1], ['30%', '70%']);
  const spotlightBackground = useMotionTemplate`radial-gradient(circle at ${spotlightX} ${spotlightY}, rgba(138, 230, 255, 0.22), rgba(138, 230, 255, 0.06) 30%, transparent 64%)`;

  const heroY = useTransform(scrollYProgress, [0, 0.34], [0, -72]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.4], [1, 0.55]);
  const visualY = useTransform(scrollYProgress, [0, 0.33], [0, -34]);
  const featuresY = useTransform(scrollYProgress, [0.14, 0.48], [44, 0]);
  const featuresOpacity = useTransform(scrollYProgress, [0.14, 0.45], [0.45, 1]);

  const visualRotateX = useTransform(smoothPointerY, [-1, 1], [7, -7]);
  const visualRotateY = useTransform(smoothPointerX, [-1, 1], [-10, 10]);
  const pulseX = useTransform(smoothPointerX, [-1, 1], [-16, 16]);
  const pulseY = useTransform(smoothPointerY, [-1, 1], [14, -14]);
  const nodeShiftAX = useTransform(smoothPointerX, [-1, 1], [-10, 10]);
  const nodeShiftAY = useTransform(smoothPointerY, [-1, 1], [10, -10]);
  const nodeShiftBX = useTransform(smoothPointerX, [-1, 1], [8, -8]);
  const nodeShiftBY = useTransform(smoothPointerY, [-1, 1], [-8, 8]);

  const handlePointerMove = useCallback(
    (event) => {
      if (reducedMotion) return;

      const bounds = event.currentTarget.getBoundingClientRect();
      const x = (event.clientX - bounds.left) / bounds.width;
      const y = (event.clientY - bounds.top) / bounds.height;

      pointerX.set((x - 0.5) * 2);
      pointerY.set((y - 0.5) * 2);
    },
    [pointerX, pointerY, reducedMotion],
  );

  const handlePointerLeave = useCallback(() => {
    pointerX.set(0);
    pointerY.set(0);
  }, [pointerX, pointerY]);

  return (
    <motion.div
      ref={rootRef}
      className="at-home"
      onMouseMove={handlePointerMove}
      onMouseLeave={handlePointerLeave}
    >
      <motion.div
        className="at-home__scroll-bar"
        style={reducedMotion ? undefined : { scaleX: scrollYProgress }}
      />
      <div className="at-home__grid" />
      <div className="at-home__noise" />
      <motion.div
        className="at-home__spotlight"
        style={reducedMotion ? undefined : { backgroundImage: spotlightBackground }}
      />
      <div className="at-home__blob at-home__blob--a" />
      <div className="at-home__blob at-home__blob--b" />
      <div className="at-home__blob at-home__blob--c" />

      {/* 3D Background Canvas */}
      <Canvas3D />

      <header className="at-home__header">
        <Link to="/" className="at-home__brand" aria-label="SentinelAI home">
          <img src="/resources/logo.svg" alt="SentinelAI" />
          <span>SentinelAI</span>
        </Link>

        <div className="at-home__header-actions">
          <Link to="/login" className="at-home__btn at-home__btn--ghost">
            Login
          </Link>
          <Link to="/service" className="at-home__btn at-home__btn--solid">
            Services
            <ArrowRight size={16} />
          </Link>
        </div>
      </header>

      <main className="at-home__content">
        <motion.section
          className="at-home__hero"
          style={reducedMotion ? undefined : { y: heroY, opacity: heroOpacity }}
        >
          <motion.p
            className="at-home__eyebrow"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Sparkles size={14} />
            AI-Native Offensive Security Platform
          </motion.p>

          <motion.h1
            className="at-home__title"
            initial={{ opacity: 0, y: 26 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.08 }}
          >
            Detect Real Risk
            <br />
            Before Attackers Do
          </motion.h1>

          <motion.p
            className="at-home__subtitle"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.18 }}
          >
            SentinelAI unifies autonomous discovery, intelligent scanning, and vulnerability triage into one high-speed workflow for modern teams.
          </motion.p>

          <motion.div
            className="at-home__hero-actions"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.28 }}
          >
            <Link to="/service" className="at-home__btn at-home__btn--solid at-home__btn--hero">
              Launch Service Console
              <ArrowRight size={16} />
            </Link>
            <Link to="/login" className="at-home__btn at-home__btn--ghost at-home__btn--hero">
              Go To Login
            </Link>
          </motion.div>

          <motion.div
            className="at-home__metrics"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.35 }}
          >
            <article>
              <h3>24/7</h3>
              <p>Autonomous surveillance cycles</p>
            </article>
            <article>
              <h3>Multi-Tool</h3>
              <p>Integrated scanner orchestration</p>
            </article>
            <article>
              <h3>AI Prioritized</h3>
              <p>Remediation-first risk ranking</p>
            </article>
          </motion.div>
        </motion.section>

        <motion.section
          className="at-home__visual"
          initial={{ opacity: 0, scale: 0.94 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.75, delay: 0.22 }}
          style={reducedMotion ? undefined : { y: visualY }}
        >
          <motion.div
            className="at-home__visual-frame"
            style={
              reducedMotion
                ? undefined
                : {
                    rotateX: visualRotateX,
                    rotateY: visualRotateY,
                  }
            }
          >
            <motion.div
              className="at-home__pulse"
              style={reducedMotion ? undefined : { x: pulseX, y: pulseY }}
            />
            <motion.div
              className="at-home__node at-home__node--a"
              style={reducedMotion ? undefined : { x: nodeShiftAX, y: nodeShiftAY }}
            />
            <motion.div
              className="at-home__node at-home__node--b"
              style={reducedMotion ? undefined : { x: nodeShiftBX, y: nodeShiftBY }}
            />
            <motion.div
              className="at-home__node at-home__node--c"
              style={reducedMotion ? undefined : { x: nodeShiftAX, y: nodeShiftBY }}
            />
            <div className="at-home__scanline" />

            <div className="at-home__console-card">
              <p className="at-home__console-label">
                <Server size={14} />
                Live Orchestration Layer
              </p>
              <h4>Threat Surface Monitor</h4>
              <ul>
                <li>
                  <CheckCircle2 size={14} />
                  Asset discovery queued
                </li>
                <li>
                  <CheckCircle2 size={14} />
                  Smart scan template selected
                </li>
                <li>
                  <CheckCircle2 size={14} />
                  AI triage confidence: 98.1%
                </li>
              </ul>
            </div>
          </motion.div>
        </motion.section>

        <motion.section
          className="at-home__features"
          style={reducedMotion ? undefined : { y: featuresY, opacity: featuresOpacity }}
        >
          {featureCards.map((feature, idx) => {
            const Icon = feature.icon;
            return (
              <motion.article
                key={feature.title}
                className="at-home__feature-card"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.35 }}
                transition={{ duration: 0.5, delay: idx * 0.1 }}
              >
                <div className="at-home__feature-icon">
                  <Icon size={20} />
                </div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </motion.article>
            );
          })}
        </motion.section>

        <section className="at-home__workflow">
          <h2>How SentinelAI Runs Your Security Cycle</h2>
          <div className="at-home__workflow-grid">
            {workflow.map((item, idx) => (
              <motion.article
                key={item.step}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.35 }}
                transition={{ duration: 0.5, delay: idx * 0.1 }}
              >
                <span>{item.step}</span>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </motion.article>
            ))}
          </div>
        </section>

        <motion.section
          className="at-home__cta"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.55 }}
        >
          <h2>Ready To Run SentinelAI On Your Targets?</h2>
          <p>
            Keep your current login and dashboard flow, now with a high-impact homepage experience in front.
          </p>
          <div className="at-home__cta-actions">
            <Link to="/service" className="at-home__btn at-home__btn--solid at-home__btn--hero">
              Open Services
              <ArrowRight size={16} />
            </Link>
            <Link to="/login" className="at-home__btn at-home__btn--ghost at-home__btn--hero">
              Open Login
            </Link>
          </div>
        </motion.section>
      </main>
    </motion.div>
  );
}
