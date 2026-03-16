import { cn } from '../lib/utils'
import type { DecisionStatus } from '../lib/types'
import { statusDotColor } from '../lib/types'

interface StatusIndicatorProps {
  status: DecisionStatus
  size?: 'sm' | 'md' | 'lg'
}

const sizeClasses: Record<string, { dot: string; text: string }> = {
  sm: { dot: 'w-2 h-2', text: 'text-xs' },
  md: { dot: 'w-2.5 h-2.5', text: 'text-sm' },
  lg: { dot: 'w-3 h-3', text: 'text-base' },
}

const statusLabels: Record<DecisionStatus, string> = {
  Created: 'Created',
  Deliberation: 'Deliberation',
  Voting: 'Voting',
  Approved: 'Approved',
  Rejected: 'Rejected',
  Void: 'Void',
  Contested: 'Contested',
  RatificationRequired: 'Ratification Required',
  RatificationExpired: 'Ratification Expired',
  DegradedGovernance: 'Degraded Governance',
}

export function StatusIndicator({ status, size = 'md' }: StatusIndicatorProps) {
  const classes = sizeClasses[size]
  const dotColor = statusDotColor(status)
  const label = statusLabels[status] || status

  return (
    <span className="inline-flex items-center gap-1.5" role="status" aria-label={`Status: ${label}`}>
      <span
        className={cn('inline-block rounded-full', classes.dot, dotColor)}
        aria-hidden="true"
      />
      <span className={cn(classes.text, 'font-medium text-text-gov-primary')}>
        {label}
      </span>
    </span>
  )
}
