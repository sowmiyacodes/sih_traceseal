import {
  Droplets,
  FileText,
  LayoutDashboard,
  LockKeyhole,
  ScrollText,
  SearchCheck,
  ShieldCheck,
  UserRound,
} from 'lucide-react'
import type { UserRole } from '../types/auth'

export type NavigationItem = {
  label: string
  path: string
  icon: typeof LayoutDashboard
  roles: UserRole[]
}

const allRoles: UserRole[] = ['ADMIN', 'SENDER', 'RECIPIENT', 'FORENSIC_INVESTIGATOR']
const operationalRoles: UserRole[] = ['ADMIN', 'SENDER']
const investigationRoles: UserRole[] = ['ADMIN', 'FORENSIC_INVESTIGATOR']

export const navigationItems: NavigationItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard, roles: allRoles },
  { label: 'Documents', path: '/documents', icon: FileText, roles: operationalRoles },
  { label: 'Distribution', path: '/distribution', icon: FileText, roles: operationalRoles },
  { label: 'Recipients', path: '/recipients', icon: UserRound, roles: operationalRoles },
  { label: 'Decryption', path: '/decryption', icon: LockKeyhole, roles: ['RECIPIENT'] },
  { label: 'Watermark Lab', path: '/watermarks', icon: Droplets, roles: operationalRoles },
  { label: 'Ledger Explorer', path: '/ledger', icon: ScrollText, roles: [...investigationRoles, 'SENDER'] },
  { label: 'Forensic Investigation', path: '/forensics', icon: SearchCheck, roles: investigationRoles },
  { label: 'Cases', path: '/cases', icon: SearchCheck, roles: investigationRoles },
  { label: 'Reports', path: '/reports', icon: FileText, roles: investigationRoles },
  { label: 'Security', path: '/security', icon: ShieldCheck, roles: allRoles },
  { label: 'Settings', path: '/settings', icon: ShieldCheck, roles: allRoles },
  { label: 'Admin Users', path: '/admin/users', icon: UserRound, roles: ['ADMIN'] },
]
