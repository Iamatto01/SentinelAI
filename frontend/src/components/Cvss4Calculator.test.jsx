import React from 'react'
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import Cvss4Calculator from './Cvss4Calculator.jsx'

describe('Cvss4Calculator', () => {
  it('renders the standard score and preset controls', () => {
    render(<Cvss4Calculator />)
    expect(screen.getByText('FIRST CVSS v4.0 Standard Score')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Remote Code Execution/i })).toBeInTheDocument()
  })
})
