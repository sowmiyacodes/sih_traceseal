import { useState } from 'react'
import { Button, Card, CardContent, Container, Stack, TextField, Typography } from '@mui/material'
import axios from 'axios'
import { API_BASE } from '../config/api'
import { whiteTheme } from '../config/theme'

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const login = async () => {
    try {
      const { data } = await axios.post(`${API_BASE}/auth/login`, { username, password })
      window.localStorage.setItem('traceseal_session', data.token)
      onLogin()
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Login failed') : 'Login failed')
    }
  }

  return (
    <Container maxWidth="sm" sx={{ pt: 12 }}>
      <Card sx={{ border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow }}>
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>TraceSeal</Typography>
          <Typography sx={{ mb: 3, color: whiteTheme.subtext }}>Offline identity gateway</Typography>
          <Stack spacing={2}>
            <TextField label="Username" value={username} onChange={(event) => setUsername(event.target.value)} />
            <TextField label="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
            <Button variant="contained" onClick={() => void login()}>Login</Button>
            {error && <Typography color="error">{error}</Typography>}
          </Stack>
        </CardContent>
      </Card>
    </Container>
  )
}
