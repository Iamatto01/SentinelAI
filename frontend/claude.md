# Senior UI Design Blueprint

Welcome AI assistant! When developing UI components for SentinelAI, strictly adhere to the following premium design guidelines. SentinelAI is a state-of-the-art automated pentesting platform, and its interface must reflect extreme technical competence, luxury, and futuristic capability.

## 1. Typography
- **Headings**: `Outfit`
  - High-impact, geometric, modern. Use for titles, dashboard numbers, and strong call-to-actions.
- **Body Text**: `Inter`
  - Highly legible, neutral, professional. Use for paragraphs, labels, and small text.
- **Monospace/Code**: `JetBrains Mono`
  - Use for terminal output, raw logs, and code snippets.
- **Rule**: Never use default browser fonts. Establish clear hierarchy using Tailwind text utilities (`text-xs` up to `text-6xl`).

## 2. Color Palette & Theming (Dark Mode First)
- **Backgrounds**: Deep, rich darks (e.g., `#09090b` or `zinc-950`).
- **Surfaces**: Use subtle glassmorphism instead of flat colors. Implement gradients and blurs: `bg-white/5 backdrop-blur-md border border-white/10`.
- **Primary Accents**: Cybernetic Blue (e.g., `#0ea5e9` to `#3b82f6` gradients) or Electric Purple (`#8b5cf6`).
- **Gradients**: Instead of solid sections, use shifting mesh gradients bounded as background elements.
- **Text**: Off-whites (`text-zinc-100`, `text-zinc-400`) instead of pure `#ffffff` to reduce eye strain.

## 3. Shadows, Depth & 3D
- Use multiple soft box-shadows to build 3D depth, e.g., `shadow-[0_8px_30px_rgb(0,0,0,0.12)]`.
- Glow effects: Add colored shadows for glowing accents (e.g., `shadow-[0_0_15px_rgba(59,130,246,0.5)]`).
- Elements should feel like they are floating on top of each other.

## 4. Animation & Easing
- **Micro-interactions**: Every interactive element (buttons, cards, links) MUST have a hover state.
  - Scale up (`hover:scale-105`)
  - Subtle brightness shifts (`hover:bg-white/10`)
- **Transitions**: Use Framer Motion for mounting/unmounting components. Avoid abrupt flashes.
- **Springs**: Favor spring animations over rigid linear transitions to make the app feel "alive".

## 5. Component Standard (Shadcn UI Approach)
- Never use raw `<button>` or `<input>`. Always build or use reusable components (`<Button>`, `<Card>`).
- Enforce strict spacing using Tailwind (`p-4`, `p-6`, `gap-4`). Avoid arbitrary magic numbers.
- Ensure perfect radial symmetry; if a card has `rounded-xl`, internal elements should have `rounded-lg` or `rounded-md` based on padding.

## 6. General Rules
- If a user requests a change, make sure it fits this premium aesthetic.
- Do not use plain Tailwind colors (e.g., `bg-red-500`) without context. Apply soft gradients or varying opacities instead.
- **WOW Factor**: Always implement the solution that looks the most impressive first.
