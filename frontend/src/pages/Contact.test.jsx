import React from 'react'
import { render, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import Contact from './Contact.jsx'

vi.mock('../components/PublicLayout.jsx', () => ({
  default: ({ children }) => <div data-testid="public-layout">{children}</div>,
}))

describe('Contact Page', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('submits inquiry to public POST /api/contact instead of authenticated /api/scans/request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'content-type': 'application/json' } })
    )

    const { getByLabelText, getByText } = render(
      <MemoryRouter>
        <Contact />
      </MemoryRouter>
    )

    fireEvent.change(getByLabelText('Name'), { target: { value: 'Alice Security' } })
    fireEvent.change(getByLabelText('Email'), { target: { value: 'alice@example.com' } })
    fireEvent.change(getByLabelText('Inquiry Type'), { target: { value: 'demo' } })
    fireEvent.change(getByLabelText('Message'), { target: { value: 'Interested in a demo for our team.' } })
    fireEvent.click(getByText('Send Message'))

    await waitFor(() => expect(getByText('Message received!')).toBeTruthy())
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/contact')
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body)
    expect(body).toEqual({
      name: 'Alice Security',
      email: 'alice@example.com',
      type: 'demo',
      message: 'Interested in a demo for our team.',
    })
  })
})
