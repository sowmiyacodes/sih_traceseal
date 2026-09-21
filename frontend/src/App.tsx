import { useEffect, useMemo, useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import axios from 'axios'
import {
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  TextField,
  Toolbar,
  Typography,
  Stack,
} from '@mui/material'
import {
  FileText,
  ShieldCheck,
  UserRound,
  LockKeyhole,
  Droplets,
  ScrollText,
  SearchCheck,
  LayoutDashboard,
} from 'lucide-react'
import './App.css'

const API_BASE = 'http://127.0.0.1:8000/api'

type DocumentRecord = {
  document_id: string
  original_filename: string
  encrypted_path?: string
  original_hash?: string
  encryption_algorithm?: string
  encryption_key_hex?: string
  decrypted_path?: string
  watermarked_path?: string
}

type DecryptResult = {
  error?: string
  document_id?: string
  encrypted_path?: string
  plaintext_path?: string
  decrypted_bytes?: number
  sha3_256?: string
  watermarked_path?: string
  watermark_id?: string
  event_id?: string
}

const navItems = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard },
  { label: 'Documents', path: '/documents', icon: FileText },
  { label: 'Recipients', path: '/recipients', icon: UserRound },
  { label: 'Decryption', path: '/decryption', icon: LockKeyhole },
  { label: 'Watermark Lab', path: '/watermarks', icon: Droplets },
  { label: 'Ledger Explorer', path: '/ledger', icon: ScrollText },
  { label: 'Forensic Investigation', path: '/forensics', icon: SearchCheck },
]

const whiteTheme = {
  shell: '#f4f7fb',
  panel: '#ffffff',
  panelAlt: '#f8fafc',
  text: '#14213d',
  subtext: '#53627a',
  muted: '#8aa0b8',
  line: '#e6edf7',
  primary: '#0b6bcb',
  primarySoft: '#eaf3ff',
  success: '#148d63',
  successSoft: '#eafaf4',
  warning: '#d97706',
  warningSoft: '#fff4e6',
  danger: '#c63838',
  dangerSoft: '#fff0f0',
  navy: '#0f172a',
  shadow: '0 12px 28px rgba(15, 23, 42, 0.08)',
}

function AppShell() {
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
          {navItems.map(({ label, path, icon: Icon }) => (
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
              Forensic Attribution Command Center
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
          </Toolbar>
        </AppBar>

        <Container maxWidth={false} sx={{ px: 0 }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/documents" element={<DocumentsPage />} />
            <Route path="/recipients" element={<RecipientsPage />} />
            <Route path="/decryption" element={<DecryptionPage />} />
            <Route path="/watermarks" element={<WatermarkPage />} />
            <Route path="/ledger" element={<LedgerPage />} />
            <Route path="/forensics" element={<ForensicsPage />} />
          </Routes>
        </Container>
      </Box>
    </Box>
  )
}

function Dashboard() {
  const [stats, setStats] = useState({ totalDocuments: '--', encrypted: '--', recipients: '--', events: '--', watermarks: '--', ledger: '--' })

  useEffect(() => {
    const loadStats = async () => {
      try {
        const { data } = await axios.get(`${API_BASE}/dashboard`)
        setStats({
          totalDocuments: String(data.total_documents ?? 0),
          encrypted: String(data.encrypted_documents ?? 0),
          recipients: String(data.registered_recipients ?? 0),
          events: String(data.decryption_events ?? 0),
          watermarks: String(data.watermark_records ?? 0),
          ledger: String(data.ledger_blocks ?? 0),
        })
      } catch {
        setStats({ totalDocuments: '0', encrypted: '0', recipients: '0', events: '0', watermarks: '0', ledger: '0' })
      }
    }
    void loadStats()
  }, [])

  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 2.5 }}>
      {Object.entries(stats).map(([label, value]) => (
        <Card key={label} sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
          <CardContent sx={{ p: 2.5 }}>
            <Typography variant="body2" sx={{ color: whiteTheme.subtext, fontWeight: 600 }}>
              {label === 'totalDocuments' ? 'Total Documents' : label === 'encrypted' ? 'Encrypted' : label === 'recipients' ? 'Recipients' : label === 'events' ? 'Events' : label === 'watermarks' ? 'Watermarks' : 'Ledger Blocks'}
            </Typography>
            <Typography variant="h4" sx={{ mt: 1.2, fontWeight: 800, color: whiteTheme.text, fontFamily: 'ui-monospace, SFMono-Regular, monospace' }}>{value}</Typography>
          </CardContent>
        </Card>
      ))}

      <Card sx={{ gridColumn: '1 / -1', background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Security Pipeline</Typography>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
            {['Authentication', 'Key establishment', 'Decryption', 'Session generation', 'Watermark generation', 'ML-DSA signing', 'Ledger commit'].map((step) => (
              <Chip key={step} label={step} sx={{ background: whiteTheme.primarySoft, color: whiteTheme.primary, border: `1px solid ${whiteTheme.primary}` }} />
            ))}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  )
}

function DocumentsPage() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [status, setStatus] = useState<string>('No upload yet')
  const [uploading, setUploading] = useState(false)
  const [latestKey, setLatestKey] = useState('')

  const loadDocuments = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/documents`)
      setDocuments(data)
    } catch {
      setDocuments([])
    }
  }

  useEffect(() => {
    void loadDocuments()
  }, [])

  const handleUpload = async () => {
    if (!selectedFile) {
      setStatus('Choose a file first.')
      return
    }
    const form = new FormData()
    form.append('file', selectedFile)
    setUploading(true)
    try {
      const { data } = await axios.post(`${API_BASE}/documents/upload`, form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setStatus(`Uploaded: ${data.original_filename} (${data.document_id})`)
      setLatestKey(data.encryption_key_hex ?? '')
      await loadDocuments()
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        setStatus(err.response?.data?.detail ?? 'Upload failed')
      } else {
        setStatus('Upload failed')
      }
    } finally {
      setUploading(false)
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Documents</Typography>
        <Box sx={{ display: 'grid', gap: 2 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <Button variant="contained" component="label" sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>
              Select file
              <input hidden type="file" onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)} />
            </Button>
            <Button variant="outlined" onClick={handleUpload} disabled={uploading || !selectedFile} sx={{ color: whiteTheme.primary, borderColor: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>
              {uploading ? 'Uploading...' : 'Upload and Encrypt'}
            </Button>
          </Box>
          <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Status: {status}</Typography>
          {latestKey && (
            <Box sx={{ background: whiteTheme.warningSoft, border: `1px solid ${whiteTheme.warning}`, borderRadius: 2, p: 2 }}>
              <Typography variant="subtitle2" sx={{ color: whiteTheme.text, fontWeight: 700 }}>Save this encryption key</Typography>
              <Typography variant="body2" sx={{ color: whiteTheme.subtext, mb: 1 }}>This key is required on the Decryption page. It is shown after upload so you can copy it.</Typography>
              <TextField value={latestKey} fullWidth InputProps={{ readOnly: true }} size="small" />
            </Box>
          )}
          {selectedFile && (
            <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Selected file: {selectedFile.name}</Typography>
          )}

          <Box sx={{ mt: 1, display: 'grid', gap: 1 }}>
            {documents.length === 0 ? (
              <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No uploaded documents found.</Typography>
            ) : (
              documents.map((doc) => (
                <Card key={doc.document_id} sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
                  <CardContent sx={{ py: 1.5 }}>
                    <Typography variant="subtitle1" sx={{ color: whiteTheme.text, fontWeight: 700 }}>{doc.original_filename}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>ID: {doc.document_id}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Hash: {doc.original_hash ?? 'n/a'}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Encrypted path: {doc.encrypted_path ?? 'n/a'}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Decrypted path: {doc.decrypted_path ?? 'Available after decryption'}</Typography>
                  </CardContent>
                </Card>
              ))
            )}
          </Box>
        </Box>
      </CardContent>
    </Card>
  )
}

function DecryptionPage() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [selectedDocumentPath, setSelectedDocumentPath] = useState('')
  const [keyHex, setKeyHex] = useState('')
  const [recipientId, setRecipientId] = useState('REC-001')
  const [result, setResult] = useState<DecryptResult | null>(null)
  const [loading, setLoading] = useState(false)

  const loadKeyForDocument = async (documentId: string) => {
    try {
      const { data } = await axios.get(`${API_BASE}/documents/${documentId}/key`)
      setKeyHex(data.key_hex ?? '')
    } catch {
      setKeyHex('')
    }
  }

  useEffect(() => {
    const loadDocuments = async () => {
      const { data } = await axios.get(`${API_BASE}/documents`)
      setDocuments(data)
      if (data[0]?.encrypted_path) {
        setSelectedDocumentPath(data[0].encrypted_path)
        void loadKeyForDocument(data[0].document_id)
      }
    }
    void loadDocuments()
  }, [])

  const keyHelperText = useMemo(() => {
    if (!keyHex) return 'Use the exact AES key used when the file was encrypted.'
    return keyHex.length === 64
      ? 'Valid 32-byte AES key format detected.'
      : 'Key should be 64 hexadecimal characters (32 bytes).'
  }, [keyHex])

  const handleDecrypt = async () => {
    if (!selectedDocumentPath || !keyHex) {
      setResult({ error: 'Choose a document and enter the decryption key.' })
      return
    }
    if (keyHex.length !== 64) {
      setResult({ error: 'The key must be exactly 64 hex characters, which is 32 bytes.' })
      return
    }
    setLoading(true)
    try {
      const { data } = await axios.post(`${API_BASE}/documents/decrypt`, {
        document_path: selectedDocumentPath,
        key_hex: keyHex,
        document_id: documents.find((doc) => doc.encrypted_path === selectedDocumentPath)?.document_id,
        recipient_id: recipientId,
      })
      setResult(data)
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        setResult({ error: err.response?.data?.detail ?? 'Decryption failed' })
      } else {
        setResult({ error: 'Decryption failed' })
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Decryption</Typography>

        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <Box sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2, p: 2 }}>
            <Typography variant="subtitle2" sx={{ color: whiteTheme.text, fontWeight: 700, mb: 1 }}>What should I enter?</Typography>
            <Typography variant="body2" sx={{ color: whiteTheme.subtext, lineHeight: 1.7 }}>
              Enter the same AES-256-GCM key used when the document was encrypted. It must be a 64-character hexadecimal value, equivalent to 32 bytes. If you do not have the original key, the file cannot be decrypted correctly.
            </Typography>
          </Box>

          <TextField
            select
            SelectProps={{ native: true }}
            label="Encrypted document"
            value={selectedDocumentPath}
            onChange={(event) => {
              setSelectedDocumentPath(event.target.value)
              const selected = documents.find((doc) => doc.encrypted_path === event.target.value)
              if (selected) void loadKeyForDocument(selected.document_id)
            }}
            fullWidth
          >
            <option value="">Select a document</option>
            {documents.map((doc) => (
              <option key={doc.document_id} value={doc.encrypted_path ?? ''}>{doc.original_filename} (encrypted)</option>
            ))}
          </TextField>

          <TextField
            label="AES decryption key"
            value={keyHex}
            onChange={(event) => setKeyHex(event.target.value.trim())}
            fullWidth
            helperText={keyHelperText}
            placeholder="Example: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
          />

          <TextField
            label="Recipient ID for this decryption session"
            value={recipientId}
            onChange={(event) => setRecipientId(event.target.value.trim())}
            fullWidth
            helperText="Use a registered recipient ID, such as REC-001. This is stored in the signed forensic event."
          />

          <Button variant="contained" onClick={handleDecrypt} disabled={loading} sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>
            {loading ? 'Decrypting...' : 'Decrypt document'}
          </Button>

          {result && (
            <Card sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
              <CardContent sx={{ py: 2 }}>
                <Typography variant="subtitle1" sx={{ mb: 1, color: whiteTheme.text, fontWeight: 700 }}>Decryption result</Typography>
                {result.error ? (
                  <Typography variant="body2" sx={{ color: whiteTheme.danger }}>{String(result.error)}</Typography>
                ) : (
                  <Box sx={{ display: 'grid', gap: 1 }}>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Document ID: {String(result.document_id ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Encrypted path: {String(result.encrypted_path ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Decrypted file: {String(result.plaintext_path ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Watermarked copy: {String(result.watermarked_path ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Watermark ID: {String(result.watermark_id ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Event ID: {String(result.event_id ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Decrypted bytes: {String(result.decrypted_bytes ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>SHA3-256: {String(result.sha3_256 ?? 'n/a')}</Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}
        </Box>
      </CardContent>
    </Card>
  )
}

function WatermarkPage() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [selectedPath, setSelectedPath] = useState('')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const loadDocuments = async () => {
      const { data } = await axios.get(`${API_BASE}/documents`)
      setDocuments(data)
      if (data[0]?.watermarked_path || data[0]?.decrypted_path) {
        setSelectedPath(data[0].watermarked_path ?? data[0].decrypted_path)
      }
    }
    void loadDocuments()
  }, [])

  const handleDetect = async () => {
    if (!selectedPath) {
      setResult({ error: 'Select a document first.' })
      return
    }
    setLoading(true)
    try {
      const { data } = await axios.post(`${API_BASE}/watermark/detect`, { document_path: selectedPath })
      setResult(data)
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        setResult({ error: err.response?.data?.detail ?? 'Watermark detection failed' })
      } else {
        setResult({ error: 'Watermark detection failed' })
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Watermark Lab</Typography>

        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <Box sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2, p: 2 }}>
            <Typography variant="subtitle2" sx={{ color: whiteTheme.text, fontWeight: 700, mb: 1 }}>How to read this section</Typography>
            <Typography variant="body2" sx={{ color: whiteTheme.subtext, lineHeight: 1.7 }}>
              The watermark check looks for a traceable document marker and reports whether it matches a known local ledger record. A match means the file may be linked to a signed decryption event; it does not by itself reveal the recipient identity without verification.
            </Typography>
          </Box>

          <TextField
            select
            SelectProps={{ native: true }}
            label="Document to inspect"
            value={selectedPath}
            onChange={(event) => setSelectedPath(event.target.value)}
            fullWidth
          >
            <option value="">Select a document</option>
            {documents.map((doc) => (
              <option key={doc.document_id} value={doc.watermarked_path ?? doc.decrypted_path ?? ''}>{doc.original_filename} ({doc.watermarked_path ? 'watermarked' : 'decrypted'})</option>
            ))}
          </TextField>

          <Button variant="contained" onClick={handleDetect} disabled={loading} sx={{ background: '#1ab39c', borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>
            {loading ? 'Scanning...' : 'Detect watermark'}
          </Button>

          {result && (
            <Card sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
              <CardContent sx={{ py: 2 }}>
                <Typography variant="subtitle1" sx={{ mb: 1, color: whiteTheme.text, fontWeight: 700 }}>Watermark result</Typography>
                {result.error ? (
                  <Typography variant="body2" sx={{ color: whiteTheme.danger }}>{String(result.error)}</Typography>
                ) : (
                  <Box sx={{ display: 'grid', gap: 1 }}>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Detected: {String(result.detected ?? false)}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Confidence: {String(result.confidence ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Watermark ID: {String(result.watermark_id ?? 'No details found')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Algorithm: {String(result.algorithm ?? 'n/a')}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Page: {String(result.page ?? 'n/a')}</Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}
        </Box>
      </CardContent>
    </Card>
  )
}

function RecipientsPage() {
  const [recipients, setRecipients] = useState<any[]>([])
  const [name, setName] = useState('')
  const [department, setDepartment] = useState('')
  const [status, setStatus] = useState('')

  const loadRecipients = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/recipients`)
      setRecipients(data)
    } catch {
      setRecipients([])
    }
  }

  useEffect(() => {
    void loadRecipients()
  }, [])

  const handleCreate = async () => {
    if (!name || !department) {
      setStatus('Name and department are required.')
      return
    }
    try {
      await axios.post(`${API_BASE}/recipients`, { name, department })
      setStatus(`Recipient created: ${name}`)
      setName('')
      setDepartment('')
      await loadRecipients()
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) setStatus(err.response?.data?.detail ?? 'Create failed')
      else setStatus('Create failed')
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Recipients</Typography>
        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth />
          <TextField label="Department" value={department} onChange={(e) => setDepartment(e.target.value)} fullWidth />
          <Button variant="contained" onClick={handleCreate} sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>Create recipient</Button>
          {status && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>{status}</Typography>}

          <Box sx={{ display: 'grid', gap: 1 }}>
            {recipients.length === 0 ? <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No recipients found.</Typography> : recipients.map((recipient) => (
              <Card key={recipient.recipient_id} sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="subtitle1" sx={{ color: whiteTheme.text, fontWeight: 700 }}>{recipient.name}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>ID: {recipient.recipient_id}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Department: {recipient.department}</Typography>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  )
}

function LedgerPage() {
  const [blocks, setBlocks] = useState<any[]>([])
  const [valid, setValid] = useState<boolean | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [{ data: blockData }, { data: validateData }] = await Promise.all([
          axios.get(`${API_BASE}/ledger/blocks`),
          axios.get(`${API_BASE}/ledger/validate`),
        ])
        setBlocks(blockData)
        setValid(validateData.valid)
      } catch {
        setBlocks([])
        setValid(null)
      }
    }
    void load()
  }, [])

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Ledger Explorer</Typography>
        <Typography variant="body2" sx={{ color: valid === true ? whiteTheme.success : valid === false ? whiteTheme.danger : whiteTheme.subtext, mb: 2, fontWeight: 700 }}>
          Chain status: {valid === null ? 'unknown' : valid ? 'valid' : 'invalid'}
        </Typography>
        <Box sx={{ display: 'grid', gap: 1 }}>
          {blocks.length === 0 ? <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No ledger blocks found.</Typography> : blocks.map((block) => (
            <Card key={block.block_number} sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
              <CardContent sx={{ py: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: whiteTheme.text, fontWeight: 700 }}>Block #{block.block_number}</Typography>
                <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Hash: {block.block_hash}</Typography>
                <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Previous: {block.previous_hash}</Typography>
              </CardContent>
            </Card>
          ))}
        </Box>
      </CardContent>
    </Card>
  )
}

function ForensicsPage() {
  const [eventId, setEventId] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleLookup = async () => {
    if (!eventId) {
      setResult({ error: 'Enter an event ID.' })
      return
    }
    setLoading(true)
    try {
      const { data } = await axios.get(`${API_BASE}/events/${eventId}`)
      setResult(data)
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) setResult({ error: err.response?.data?.detail ?? 'Event not found' })
      else setResult({ error: 'Event not found' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Forensic Investigation</Typography>
        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <TextField label="Event ID" value={eventId} onChange={(e) => setEventId(e.target.value)} fullWidth />
          <Button variant="contained" onClick={handleLookup} disabled={loading} sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>{loading ? 'Loading...' : 'Lookup event'}</Button>

          {result && (
            <Card sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
              <CardContent sx={{ py: 2 }}>
                {result.error ? (
                  <Typography variant="body2" sx={{ color: whiteTheme.danger }}>{result.error}</Typography>
                ) : (
                  <Box sx={{ display: 'grid', gap: 1 }}>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Event ID: {result.event_id}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Recipient: {result.recipient_id}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Session: {result.session_id}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Watermark: {result.watermark_id}</Typography>
                    <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Signature: {result.signature_algorithm}</Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}
        </Box>
      </CardContent>
    </Card>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}

export default App
