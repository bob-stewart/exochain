# decision.forum — Multi-Device Layout Specification

## Breakpoints

| Name | Min Width | Target Device | Layout Strategy |
|------|-----------|---------------|-----------------|
| `mobile` | 0px | Phone (portrait) | Single column, bottom nav, cards |
| `tablet` | 768px | iPad / Android tablet | Collapsible sidebar, wider cards |
| `desktop` | 1280px | Laptop / monitor | Three-panel situation room |

## Desktop Layout (≥1280px): The Situation Room

```
┌──────────────────────────────────────────────────────────────────────┐
│ HEADER: Logo + Global Nav + Search + User/Notifications             │
├────────────┬─────────────────────────────────────────────────────────┤
│ AMBIENT    │ MAIN CONTENT AREA                                       │
│ SIDEBAR    │                                                         │
│ (240px)    │ Varies by route:                                        │
│            │ • Command View (decision grid/list)                     │
│ ┌────────┐ │ • Decision Dossier (full detail)                        │
│ │Pending │ │ • Authority Map (delegation graph)                      │
│ │  3     │ │ • Audit Ledger (event feed)                             │
│ ├────────┤ │ • Constitution (framework view)                         │
│ │Overdue │ │ • Create Decision (form)                                │
│ │  1     │ │                                                         │
│ ├────────┤ │                                                         │
│ │Voting  │ │                                                         │
│ │  2     │ │                                                         │
│ ├────────┤ │                                                         │
│ │Health  │ │                                                         │
│ │  ● OK  │ │                                                         │
│ ├────────┤ │                                                         │
│ │Chain   │ │                                                         │
│ │  ✓ 24  │ │                                                         │
│ └────────┘ │                                                         │
│            │                                                         │
│ QUICK NAV  │                                                         │
│ ┌────────┐ │                                                         │
│ │Command │ │                                                         │
│ │Deleg.  │ │                                                         │
│ │Audit   │ │                                                         │
│ │Const.  │ │                                                         │
│ │+ New   │ │                                                         │
│ └────────┘ │                                                         │
├────────────┴─────────────────────────────────────────────────────────┤
│ FOOTER: Constitution version + Chain integrity + © info              │
└──────────────────────────────────────────────────────────────────────┘
```

**Keyboard Shortcuts (Desktop):**
- `G D` → Go to Dashboard/Command View
- `G N` → Go to New Decision
- `G A` → Go to Audit Trail
- `G L` → Go to Delegations
- `J/K` → Navigate between decisions in list
- `Enter` → Open selected decision
- `Esc` → Back to list
- `?` → Show keyboard shortcut overlay

## Tablet Layout (768px–1279px): The Mission Console

```
┌──────────────────────────────────────────────┐
│ HEADER: Logo + Hamburger + Search + User     │
├──────────────────────────────────────────────┤
│ AMBIENT STATUS BAR (collapsible)             │
│ [Pending: 3] [Overdue: 1] [Health: ●] [✓24] │
├──────────────────────────────────────────────┤
│                                               │
│ MAIN CONTENT AREA                            │
│ (full width, scrollable)                     │
│                                               │
│ Same views as desktop but single-column       │
│ with wider cards and more breathing room      │
│                                               │
├──────────────────────────────────────────────┤
│ BOTTOM TAB BAR (if sidebar hidden)           │
│ [Command] [Delegations] [Audit] [+ New]      │
└──────────────────────────────────────────────┘
```

**Tablet-Specific Behaviors:**
- Sidebar collapsed by default, opens as overlay on hamburger tap
- Status bar collapses to icon row on scroll-down, expands on scroll-up
- Decision cards show 2-column grid
- Swipe between OODA phases in Decision Dossier

## Mobile Layout (<768px): The Triage Board

```
┌──────────────────────────┐
│ HEADER: Logo + ≡ + 🔔    │
├──────────────────────────┤
│                           │
│ SINGLE COLUMN CONTENT     │
│                           │
│ ┌──────────────────────┐ │
│ │ Decision Brief Card  │ │
│ │ [Title          ] 🔴 │ │
│ │ [Status] [Deadline]  │ │
│ │ [Action Button     ] │ │
│ └──────────────────────┘ │
│                           │
│ ┌──────────────────────┐ │
│ │ Decision Brief Card  │ │
│ │ [Title          ] 🟡 │ │
│ │ [Status] [Deadline]  │ │
│ │ [Action Button     ] │ │
│ └──────────────────────┘ │
│                           │
│         ...               │
│                           │
├──────────────────────────┤
│ ◉ Command  📋 Audit      │
│ 🔗 Deleg.  ＋ New        │
└──────────────────────────┘
```

**Mobile-Specific Behaviors:**
- Bottom navigation bar with 4 tabs (fixed)
- Pull-to-refresh on all list views
- Decision detail opens as full-screen view (not modal)
- Actions via prominent buttons (no swipe-to-act in v1, simpler)
- Ambient status shown as badge counts on nav icons

## Component Behavior Per Breakpoint

| Component | Mobile (<768px) | Tablet (768-1279px) | Desktop (≥1280px) |
|-----------|-----------------|---------------------|-------------------|
| **Sidebar** | Hidden (hamburger menu) | Collapsible overlay | Always visible (240px) |
| **Ambient Status** | Badge counts on nav | Collapsible top bar | Sidebar section |
| **Decision Cards** | Single column, compact | 2-column grid | List rows or 3-column grid |
| **Decision Detail** | Full-screen page | Full-width with back | Main content area |
| **OODA Rail** | Current phase indicator | Swipeable tabs | Full horizontal rail |
| **Delegation Graph** | Linear chain list | Simplified tree | Full interactive graph |
| **Timeline** | Vertical, compact | Vertical, expanded | Horizontal, full |
| **Vote Actions** | Full-width bottom buttons | Inline buttons | Inline buttons |
| **Audit Feed** | Card list | Table | Table with filters |
| **Constitution** | Accordion sections | Two-column layout | Full-width sections |
| **Create Form** | Stacked fields | Two-column form | Two-column with live preview |
| **Search** | Full-screen overlay | Header input (expanding) | Header input (persistent) |
| **Keyboard Shortcuts** | N/A | N/A | Full shortcut support |
| **Navigation** | Bottom tab bar (4 items) | Bottom tab bar + hamburger | Sidebar navigation |

## Color System (Governance-Grade)

```
// Urgency indicators
--urgency-critical:  #DC2626  (red-600)    — Overdue, blocked, contested
--urgency-high:      #EA580C  (orange-600) — Due today, needs attention
--urgency-moderate:  #CA8A04  (yellow-600) — Due this week
--urgency-low:       #16A34A  (green-600)  — On track, no action needed
--urgency-neutral:   #6B7280  (gray-500)   — Informational, terminal

// Decision status (refined from current)
--status-created:     #94A3B8  (slate-400)
--status-deliberation:#3B82F6  (blue-500)
--status-voting:      #EAB308  (yellow-500)
--status-approved:    #22C55E  (green-500)
--status-rejected:    #EF4444  (red-500)
--status-void:        #6B7280  (gray-500)
--status-contested:   #F97316  (orange-500)
--status-ratification:#8B5CF6  (purple-500)
--status-expired:     #991B1B  (red-800)
--status-degraded:    #D97706  (amber-600)

// Surface hierarchy (dark professional theme option)
--surface-base:      #0F172A  (slate-900)   — Primary background
--surface-raised:    #1E293B  (slate-800)   — Cards, panels
--surface-overlay:   #334155  (slate-700)   — Modals, dropdowns
--text-primary:      #F8FAFC  (slate-50)    — Primary text
--text-secondary:    #94A3B8  (slate-400)   — Secondary text
--border-subtle:     #334155  (slate-700)   — Subtle borders

// Light theme (default)
--surface-base:      #F8FAFC  (slate-50)    — Primary background
--surface-raised:    #FFFFFF  (white)        — Cards, panels
--surface-overlay:   #F1F5F9  (slate-100)   — Modals, dropdowns
--text-primary:      #0F172A  (slate-900)   — Primary text
--text-secondary:    #64748B  (slate-500)   — Secondary text
--border-subtle:     #E2E8F0  (slate-200)   — Subtle borders
--accent-primary:    #2563EB  (blue-600)    — Primary actions
--accent-hover:      #1D4ED8  (blue-700)    — Hover state
```

## Typography Scale

```
--font-display:   'Inter', system-ui, sans-serif
--font-mono:      'JetBrains Mono', 'Fira Code', monospace  (hashes, IDs)

--text-2xs:   0.625rem (10px)  — Hash previews, timestamps
--text-xs:    0.75rem  (12px)  — Metadata labels, audit hashes
--text-sm:    0.875rem (14px)  — Body text, card content
--text-base:  1rem     (16px)  — Primary body text
--text-lg:    1.125rem (18px)  — Section headings
--text-xl:    1.25rem  (20px)  — Page titles
--text-2xl:   1.5rem   (24px)  — Dashboard numbers, KPI values
--text-3xl:   1.875rem (30px)  — Hero metrics
```
