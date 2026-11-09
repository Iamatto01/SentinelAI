import React from 'react'
import { render } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import FindingDetailDrawer from './FindingDetailDrawer.jsx'

vi.mock('../lib/AiContext.jsx', () => ({
  useAi: () => ({
    getFindingChat: () => [],
    sendFindingAiQuery: vi.fn(),
    activeTasks: {},
    activeTabOverride: null,
    setActiveTabOverride: vi.fn(),
  }),
}))

vi.mock('../lib/api.js', () => ({ api: { findingNotes: vi.fn().mockResolvedValue([]) } }))

describe('FindingDetailDrawer', () => {
  it('renders nothing when no finding is selected', () => {
    const { container } = render(<FindingDetailDrawer finding={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})
