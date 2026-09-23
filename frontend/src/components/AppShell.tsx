import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { AppBar, Box, Button, Chip, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Toolbar, Typography } from '@mui/material'
import { ShieldCheck } from 'lucide-react'
import { whiteTheme } from '../config/theme'
import { navigationItems } from '../config/navigation'
import type { AuthUser } from '../types/auth'

type AppShellProps = {
  user: AuthUser
  onLogout: () => void
  children: ReactNode
}

export function AppShell({ user, onLogout, children }: AppShellProps) {
  const visibleNavigation = navigationItems.filter((item) => item.roles.includes(user.role))
  const roleLabel = user.role === 'FORENSIC_INVESTIGATOR' ? 'Investigator workspace' : `${user.role.toLowerCase()} workspace`

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', background: whiteTheme.shell }}>
      <Drawer
        variant="permanent"
        sx={{
          width: 260,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: 260,
            background: '#ffffff',
            color: whiteTheme.text,
            borderRight: `1px solid ${whiteTheme.line}`,
            boxShadow: 'none',
          },
        }}
      >
        <Toolbar sx={{ px: 2.5, borderBottom: `1px solid ${whiteTheme.line}` }}>
          <ShieldCheck size={20} color={whiteTheme.primary} />
          <Typography variant="h6" sx={{ ml: 1.25, fontWeight: 800, letterSpacing: 0.8, color: whiteTheme.text }}>
            TRACESEAL
          </Typography>
        </Toolbar>
        <List sx={{ px: 1.25, py: 1.5 }}>
          {visibleNavigation.map(({ label, path, icon: Icon }) => (
            <ListItemButton
              key={label}
              component={NavLink}
              to={path}
              sx={{
                color: whiteTheme.text,
                borderRadius: 2,
                mb: 0.5,
                '&.active': {
                  background: whiteTheme.primarySoft,
                  color: whiteTheme.primary,
                  '& .MuiListItemIcon-root': { color: whiteTheme.primary },
                },
              }}
            >
              <ListItemIcon sx={{ color: whiteTheme.subtext, minWidth: 36 }}><Icon size={18} /></ListItemIcon>
              <ListItemText primary={label} />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
        <AppBar
          position="static"
          elevation={0}
          sx={{
            borderRadius: 3,
            background: whiteTheme.panel,
            border: `1px solid ${whiteTheme.line}`,
            boxShadow: whiteTheme.shadow,
            mb: 3,
          }}
        >
          <Toolbar sx={{ px: 2.5, minHeight: 72 }}>
            <ShieldCheck size={20} color={whiteTheme.primary} />
            <Typography variant="h6" sx={{ ml: 1.2, fontWeight: 700, color: whiteTheme.text }}>
              {roleLabel}
            </Typography>
            <Chip
              label="LOCAL VALIDATION"
              sx={{
                ml: 'auto',
                background: whiteTheme.successSoft,
                color: whiteTheme.success,
                border: `1px solid ${whiteTheme.success}`,
                fontWeight: 700,
              }}
            />
            <Chip label={user.display_name} sx={{ ml: 1, color: whiteTheme.text }} />
            <Button onClick={onLogout} sx={{ ml: 1, textTransform: 'none' }}>Logout</Button>
          </Toolbar>
        </AppBar>

        {children}
      </Box>
    </Box>
  )
}
