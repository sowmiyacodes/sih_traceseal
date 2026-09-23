import { Box, Chip, Stack, Typography } from '@mui/material'
import { Check, CircleDot, FileDown, FileSearch, KeyRound, LockKeyhole, PenLine, Upload, UserRound } from 'lucide-react'
import { whiteTheme } from '../config/theme'

type WorkflowStep = {
  label: string
  detail: string
  icon: typeof Upload
}

const steps: WorkflowStep[] = [
  { label: 'Upload', detail: 'Encrypt the source document', icon: Upload },
  { label: 'Assign recipient', detail: 'Create an isolated key package', icon: UserRound },
  { label: 'Recipient decrypts', detail: 'Authorize access server-side', icon: LockKeyhole },
  { label: 'Session watermark', detail: 'Bind a unique session marker', icon: CircleDot },
  { label: 'ML-DSA sign', detail: 'Sign the decryption event', icon: PenLine },
  { label: 'Offline DLT', detail: 'Commit the signed event locally', icon: KeyRound },
  { label: 'Download copy', detail: 'Deliver the watermarked file', icon: FileDown },
  { label: 'Upload leak', detail: 'Submit recovered evidence', icon: Upload },
  { label: 'Extract watermark', detail: 'Read the embedded marker', icon: FileSearch },
  { label: 'Verify and identify', detail: 'Match ledger, signature, and recipient', icon: Check },
]

export function WorkflowPipeline() {
  return (
    <Box sx={{ borderTop: `1px solid ${whiteTheme.line}`, pt: 2.5 }}>
      <Typography variant="h6" sx={{ mb: 0.5, color: whiteTheme.text, fontWeight: 700 }}>Traceability pipeline</Typography>
      <Typography variant="body2" sx={{ mb: 2, color: whiteTheme.subtext }}>
        Every handoff is recorded locally, from recipient assignment through forensic attribution.
      </Typography>
      <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
        {steps.map(({ label, detail, icon: Icon }, index) => (
          <Chip
            key={label}
            icon={<Icon size={15} />}
            label={`${index + 1}. ${label}`}
            title={detail}
            sx={{
              height: 34,
              background: index === steps.length - 1 ? whiteTheme.successSoft : whiteTheme.primarySoft,
              color: index === steps.length - 1 ? whiteTheme.success : whiteTheme.primary,
              border: `1px solid ${index === steps.length - 1 ? whiteTheme.success : whiteTheme.primary}`,
              fontWeight: 700,
              '& .MuiChip-icon': { color: 'inherit' },
            }}
          />
        ))}
      </Stack>
    </Box>
  )
}
