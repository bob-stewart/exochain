import { cn } from '../lib/utils'
import type { UrgencyLevel } from '../lib/types'

interface UrgencyBadgeProps {
  level: UrgencyLevel
  label?: string
}

const urgencyStyles: Record<UrgencyLevel, string> = {
  critical: 'bg-red-100 text-urgency-critical border-urgency-critical/20',
  high: 'bg-orange-100 text-urgency-high border-urgency-high/20',
  moderate: 'bg-yellow-100 text-urgency-moderate border-urgency-moderate/20',
  low: 'bg-green-100 text-urgency-low border-urgency-low/20',
  neutral: 'bg-gray-100 text-urgency-neutral border-urgency-neutral/20',
}

const defaultLabels: Record<UrgencyLevel, string> = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Moderate',
  low: 'Low',
  neutral: 'Neutral',
}

export function UrgencyBadge({ level, label }: UrgencyBadgeProps) {
  const displayLabel = label ?? defaultLabels[level]

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold',
        urgencyStyles[level]
      )}
      role="status"
      aria-label={`Urgency: ${displayLabel}`}
    >
      {displayLabel}
    </span>
  )
}
