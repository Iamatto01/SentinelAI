import React from 'react'
import { render, fireEvent, waitFor } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import FindingDetailDrawer from './FindingDetailDrawer.jsx'

let mockOverride = null
const mockSetOverride = vi.fn((v) => { mockOverride = v })
const mockFindingNotes = vi.fn().mockResolvedValue([])
const mockCheckExploit = vi.fn().mockResolvedValue({ exploitable: false, modules: [] })

vi.mock('../lib/AiContext.jsx', () => ({
  useAi: () => ({
    getFindingChat: () => [],
    sendFindingAiQuery: vi.fn(),
    activeTasks: {},
    activeTabOverride: mockOverride,
    setActiveTabOverride: mockSetOverride,
  }),
}))

vi.mock('../lib/api.js', () => ({
  api: {
    findingNotes: (...args) => mockFindingNotes(...args),
    checkExploit: (...args) => mockCheckExploit(...args),
    pocindexCve: vi.fn().mockResolvedValue(null),
  },
}))

const SAMPLE_FINDING = {
  id: 'f-1',
  title: 'Test SQL Injection',
  severity: 'high',
  status: 'open',
  url: 'https://example.test/search',
  description: 'Sample finding description',
}

describe('FindingDetailDrawer', () => {
  beforeEach(() => {
    mockOverride = null
    mockSetOverride.mockClear()
    mockFindingNotes.mockClear()
    mockCheckExploit.mockClear()
  })

  it('renders nothing when no finding is selected', () => {
    const { container } = render(<FindingDetailDrawer finding={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('transitions null -> finding -> null -> finding cleanly without Rules of Hooks crashes', async () => {
    const { rerender, queryByText } = render(<FindingDetailDrawer finding={null} onClose={vi.fn()} />)
    expect(queryByText('Test SQL Injection')).toBeNull()

    rerender(<FindingDetailDrawer finding={SAMPLE_FINDING} onClose={vi.fn()} />)
    await waitFor(() => expect(queryByText('Test SQL Injection')).toBeTruthy())

    rerender(<FindingDetailDrawer finding={null} onClose={vi.fn()} />)
    expect(queryByText('Test SQL Injection')).toBeNull()

    rerender(<FindingDetailDrawer finding={{ ...SAMPLE_FINDING, id: 'f-2', title: 'Reflected XSS' }} onClose={vi.fn()} />)
    await waitFor(() => expect(queryByText('Reflected XSS')).toBeTruthy())
  })

  it('preserves activeTabOverride after clearing it instead of resetting back to overview', async () => {
    mockOverride = 'cve'
    const { rerender, getByText } = render(
      <FindingDetailDrawer finding={SAMPLE_FINDING} onClose={vi.fn()} />
    )
    await waitFor(() => expect(mockSetOverride).toHaveBeenCalledWith(null))
    rerender(<FindingDetailDrawer finding={SAMPLE_FINDING} onClose={vi.fn()} />)

    const cveTabBtn = getByText('CVE').closest('button')
    expect(cveTabBtn.className).toContain('border-accent')
    expect(mockFindingNotes).toHaveBeenCalledTimes(1)

    fireEvent.click(getByText('Overview').closest('button'))
    expect(getByText('Overview').closest('button').className).toContain('border-accent')
  })
})
