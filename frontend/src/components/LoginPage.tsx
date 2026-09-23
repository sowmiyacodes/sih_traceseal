import { useState } from 'react'
import type { FormEvent } from 'react'
import { Alert, Box, Button, Card, CardContent, Container, Divider, Stack, TextField, Typography } from '@mui/material'
import { ArrowRight, LockKeyhole, ShieldCheck, WifiOff } from 'lucide-react'
import axios from 'axios'
import { API_BASE } from '../config/api'
import { whiteTheme } from '../config/theme'

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const fillDemo = (role: 'admin' | 'recipient') => {
    setUsername(role === 'admin' ? 'admin' : 'alice')
    setPassword(role === 'admin' ? 'traceseal-admin' : 'traceseal-alice')
    setError('')
  }

  const login = async (event?: FormEvent<HTMLFormElement>) => {
    event?.preventDefault()
    setError('')
    if (!username.trim() || !password) {
      setError('Enter your username and password to continue.')
      return
    }
    try {
      const { data } = await axios.post(`${API_BASE}/auth/login`, { username, password })
      window.localStorage.setItem('traceseal_session', data.token)
      onLogin()
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Login failed') : 'Login failed')
    }
  }

  return (
    <Box className="login-page">
      <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 1 }}>
        <Box className="login-layout">
          <Box className="login-intro">
            <Box className="login-brand"><ShieldCheck size={22} /><Typography variant="overline">TRACESEAL</Typography></Box>
            <Typography variant="h1">Evidence that remembers who touched it.</Typography>
            <Typography className="login-lead">A local-first document chain for controlled delivery, session watermarks, and forensic attribution.</Typography>
            <Stack spacing={1.5} className="login-signals">
              <Box><WifiOff size={18} /><Typography variant="body2">Offline by design</Typography></Box>
              <Box><LockKeyhole size={18} /><Typography variant="body2">Encrypted recipient access</Typography></Box>
              <Box><ShieldCheck size={18} /><Typography variant="body2">Signed, verifiable events</Typography></Box>
            </Stack>
          </Box>

          <Card className="login-card">
            <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
              <Typography variant="overline" sx={{ color: whiteTheme.primary, fontWeight: 800, letterSpacing: 1.4 }}>SECURE ACCESS</Typography>
              <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 800, color: whiteTheme.text }}>Sign in to your workspace</Typography>
              <Typography variant="body2" sx={{ mt: 1, color: whiteTheme.subtext }}>Use the credentials issued by your TraceSeal administrator.</Typography>
              <Divider sx={{ my: 3 }} />
              <Box component="form" onSubmit={(event) => void login(event)}>
                <Stack spacing={2}>
                  <TextField label="Username" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" autoFocus fullWidth />
                  <TextField label="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" fullWidth />
                  {error && <Alert severity="error">{error}</Alert>}
                  <Button type="submit" variant="contained" endIcon={<ArrowRight size={18} />} fullWidth sx={{ minHeight: 48, background: whiteTheme.primary, textTransform: 'none', fontWeight: 800 }}>
                    Enter workspace
                  </Button>
                </Stack>
              </Box>
              <Box sx={{ mt: 3 }}>
                <Typography variant="caption" sx={{ color: whiteTheme.subtext }}>LOCAL DEMO ACCESS</Typography>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ mt: 1 }}>
                  <Button size="small" variant="outlined" onClick={() => fillDemo('admin')} sx={{ flex: 1, textTransform: 'none' }}>Fill admin</Button>
                  <Button size="small" variant="outlined" onClick={() => fillDemo('recipient')} sx={{ flex: 1, textTransform: 'none' }}>Fill recipient</Button>
                </Stack>
              </Box>
              <Typography variant="caption" sx={{ display: 'block', mt: 3, color: whiteTheme.subtext, textAlign: 'center' }}>
                Demo accounts are local-only · No external authentication
              </Typography>
            </CardContent>
          </Card>
        </Box>
      </Container>
    </Box>
  )
}
