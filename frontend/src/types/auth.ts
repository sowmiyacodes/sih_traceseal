export type UserRole = 'ADMIN' | 'SENDER' | 'RECIPIENT' | 'FORENSIC_INVESTIGATOR'

export type AuthUser = {
  user_id: string
  username: string
  display_name: string
  role: UserRole
  recipient_id?: string | null
  active: boolean
  created_at?: string | null
}
