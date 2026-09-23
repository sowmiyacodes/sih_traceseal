import { Box, Chip, Stack, Typography } from '@mui/material'
import { ArrowDown, Check, CircleAlert } from 'lucide-react'
import { whiteTheme } from '../config/theme'

type EvidenceNode = { id: string; type: string; label: string; status: string }
type EvidenceGraphProps = { nodes: EvidenceNode[] }

export function EvidenceGraph({ nodes }: EvidenceGraphProps) {
  return (
    <Box sx={{ mt: 2, p: 2, border: `1px solid ${whiteTheme.line}`, borderRadius: 2, background: '#fff' }}>
      <Typography variant="subtitle2" sx={{ mb: 1.5, color: whiteTheme.text }}>Forensic Evidence Graph</Typography>
      <Stack spacing={0.75} alignItems="center">
        {nodes.map((node, index) => (
          <Box key={node.id} sx={{ width: '100%', maxWidth: 520 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1, px: 1.5, py: 1, border: `1px solid ${node.status === 'PASS' ? '#8ed4b3' : '#f0a2a2'}`, borderLeft: `4px solid ${node.status === 'PASS' ? whiteTheme.success : whiteTheme.danger}`, borderRadius: 1.5, background: node.status === 'PASS' ? whiteTheme.successSoft : whiteTheme.dangerSoft }}>
              <Box><Typography variant="caption" sx={{ display: 'block', color: whiteTheme.subtext, fontWeight: 800 }}>{node.type}</Typography><Typography variant="body2" sx={{ color: whiteTheme.text, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis' }}>{node.label}</Typography></Box>
              <Chip size="small" icon={node.status === 'PASS' ? <Check size={14} /> : <CircleAlert size={14} />} label={node.status} color={node.status === 'PASS' ? 'success' : 'error'} />
            </Box>
            {index < nodes.length - 1 && <Box sx={{ height: 22, display: 'grid', placeItems: 'center', color: whiteTheme.muted }}><ArrowDown size={16} /></Box>}
          </Box>
        ))}
      </Stack>
    </Box>
  )
}
