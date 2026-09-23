import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import axios from 'axios'
import { API_BASE } from './config/api'
import { whiteTheme } from './config/theme'
import type { AuthUser } from './types/auth'
import { LoginPage } from './components/LoginPage'
import { AppShell } from './components/AppShell'
import { WorkflowPipeline } from './components/WorkflowPipeline'
import { EvidenceGraph } from './components/EvidenceGraph'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Autocomplete,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
  Stack,
} from '@mui/material'
import './App.css'

axios.interceptors.request.use((config) => {
  const token = window.localStorage.getItem('traceseal_session')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

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
  download_error?: string
  document_id?: string
  encrypted_path?: string
  plaintext_path?: string
  decrypted_bytes?: number
  sha3_256?: string
  watermarked_path?: string
  watermark_id?: string
  event_id?: string
  download_url?: string
  download_filename?: string
}

function Dashboard({ user }: { user: AuthUser }) {
  const [stats, setStats] = useState({ totalDocuments: '--', encrypted: '--', recipients: '--', events: '--', watermarks: '--', ledger: '--' })
  const roleDescription = {
    ADMIN: 'Manage identities, encryption, distribution, and system integrity.',
    SENDER: 'Encrypt sensitive documents and distribute recipient packages.',
    RECIPIENT: 'Access assigned documents and create traceable download copies.',
    FORENSIC_INVESTIGATOR: 'Analyze leaked evidence and verify signed provenance.',
  }[user.role]

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
    <Box sx={{ display: 'grid', gap: 2.5 }}>
      <Card sx={{ background: whiteTheme.navy, color: '#ffffff', borderRadius: 3, boxShadow: whiteTheme.shadow }}>
        <CardContent sx={{ p: 3 }}>
          <Typography variant="overline" sx={{ color: '#8ec5ff', letterSpacing: 1.2 }}>{user.role} WORKSPACE</Typography>
          <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 800 }}>Welcome, {user.display_name}</Typography>
          <Typography sx={{ mt: 1, color: '#c6d8ec' }}>{roleDescription}</Typography>
          <Typography variant="caption" sx={{ display: 'block', mt: 1.5, color: '#8ec5ff' }}>SESSION: {user.user_id} · ROLE: {user.role}{user.recipient_id ? ` · RECIPIENT: ${user.recipient_id}` : ''}</Typography>
        </CardContent>
      </Card>
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
      </Box>

      <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ color: whiteTheme.text, fontWeight: 700 }}>{user.role === 'RECIPIENT' ? 'My secure activity' : user.role === 'FORENSIC_INVESTIGATOR' ? 'Investigation control room' : 'Administrative control room'}</Typography>
          <Typography variant="body2" sx={{ mt: 1, color: whiteTheme.subtext }}>{user.role === 'RECIPIENT' ? 'Assigned documents, protected downloads, and notification status are isolated to your recipient identity.' : user.role === 'FORENSIC_INVESTIGATOR' ? 'Review leaked evidence, signed events, graph relationships, and ledger integrity.' : 'Manage recipients, user access, encrypted documents, distribution, and system integrity.'}</Typography>
        </CardContent>
      </Card>

      <Card sx={{ gridColumn: '1 / -1', background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <WorkflowPipeline />
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
  const [selectedDocument, setSelectedDocument] = useState<DocumentRecord | null>(null)
  const [documentName, setDocumentName] = useState('')

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
          <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>AES-256-GCM encrypts one document ciphertext. Recipient packages are created separately with ML-KEM-768.</Typography>
          {selectedFile && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Selected file: {selectedFile.name}</Typography>}
          <Box sx={{ mt: 1, display: 'grid', gap: 1 }}>
            {documents.length === 0 ? <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No uploaded documents found.</Typography> : documents.map((doc) => (
              <Card key={doc.document_id} sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="subtitle1" sx={{ color: whiteTheme.text, fontWeight: 700 }}>{doc.original_filename}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>ID: {doc.document_id}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Hash: {doc.original_hash ?? 'n/a'}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Encrypted path: {doc.encrypted_path ?? 'n/a'}</Typography>
                  <Button size="small" variant="outlined" onClick={() => { setSelectedDocument(doc); setDocumentName(doc.original_filename) }}>Manage</Button>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>
        <Dialog open={Boolean(selectedDocument)} onClose={() => setSelectedDocument(null)} fullWidth maxWidth="sm">
          <DialogTitle>Manage document</DialogTitle>
          <DialogContent dividers>{selectedDocument && <Stack spacing={2} sx={{ pt: 1 }}><TextField label="Document filename" value={documentName} onChange={(event) => setDocumentName(event.target.value)} fullWidth /><Typography>ID: {selectedDocument.document_id}</Typography><Typography>Hash: {selectedDocument.original_hash ?? 'n/a'}</Typography><Typography>Encryption: {selectedDocument.encryption_algorithm ?? 'AES-256-GCM'}</Typography><Typography>Watermarked copy: {selectedDocument.watermarked_path ? 'Available' : 'Not created'}</Typography></Stack>}</DialogContent>
          <DialogActions><Button onClick={() => setSelectedDocument(null)}>Cancel</Button><Button variant="contained" onClick={() => { if (!selectedDocument) return; void axios.patch(`${API_BASE}/documents/${selectedDocument.document_id}`, { original_filename: documentName }).then(() => { setStatus('Document updated'); setSelectedDocument(null); return loadDocuments() }).catch((err) => setStatus(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Update failed') : 'Update failed')) }}>Save changes</Button><Button color="error" onClick={() => { if (!selectedDocument) return; void axios.delete(`${API_BASE}/documents/${selectedDocument.document_id}`).then(() => { setSelectedDocument(null); return loadDocuments() }).catch((err) => setStatus(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Delete failed') : 'Delete failed')) }}>Delete document</Button></DialogActions>
        </Dialog>
      </CardContent>
    </Card>
  )
}

function DistributionPage() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [recipients, setRecipients] = useState<any[]>([])
  const [documentId, setDocumentId] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [status, setStatus] = useState('')
  useEffect(() => { void Promise.all([axios.get(`${API_BASE}/documents`), axios.get(`${API_BASE}/recipients`)]).then(([docs, recipientData]) => { setDocuments(docs.data); setRecipients(recipientData.data) }).catch(() => setStatus('Unable to load distribution data.')) }, [])
  const distribute = async () => {
    if (!documentId || selected.length === 0) { setStatus('Choose a document and at least one recipient.'); return }
    try { const { data } = await axios.post(`${API_BASE}/documents/${documentId}/distribution`, { recipient_ids: selected }); setStatus(`Created ${data.packages.length} recipient packages from one ciphertext.`) } catch (err: unknown) { setStatus(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Distribution failed') : 'Distribution failed') }
  }
  return <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}><CardContent sx={{ p: 3 }}><Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Distribution</Typography><Stack spacing={2}><Autocomplete options={documents} value={documents.find((doc) => doc.document_id === documentId) ?? null} getOptionLabel={(doc) => `${doc.original_filename} (${doc.document_id})`} onChange={(_, value) => setDocumentId(value?.document_id ?? '')} renderInput={(params) => <TextField {...params} label="Search encrypted documents" />} /><Typography variant="subtitle2">Authorized recipients</Typography><Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Select one or more recipients. One document ciphertext will receive one key package per selected recipient.</Typography>{recipients.map((recipient) => <label key={recipient.recipient_id}><input type="checkbox" checked={selected.includes(recipient.recipient_id)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, recipient.recipient_id] : current.filter((id) => id !== recipient.recipient_id))} /> {recipient.name} ({recipient.recipient_id})</label>)}<Typography variant="body2" sx={{ color: whiteTheme.primary, fontWeight: 700 }}>{selected.length} recipient{selected.length === 1 ? '' : 's'} selected</Typography><Button variant="contained" onClick={distribute} disabled={!documentId || selected.length === 0} sx={{ background: whiteTheme.primary, textTransform: 'none' }}>Create recipient packages</Button>{status && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>{status}</Typography>}</Stack></CardContent></Card>
}

function DecryptionPage() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [selectedDocumentId, setSelectedDocumentId] = useState('')
  const [result, setResult] = useState<DecryptResult | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const loadDocuments = async () => {
      const { data } = await axios.get(`${API_BASE}/documents`)
      setDocuments(data)
      if (data[0]) setSelectedDocumentId(data[0].document_id)
    }
    void loadDocuments()
  }, [])

  const handleDecrypt = async () => {
    if (!selectedDocumentId) {
      setResult({ error: 'Choose a document.' })
      return
    }
    setLoading(true)
    try {
      const { data } = await axios.post(`${API_BASE}/documents/decrypt`, { document_id: selectedDocumentId })
      setResult(data)
      if (data.watermark_id) {
        try {
          await downloadCopy(data.download_url ?? `/api/documents/${data.document_id}/download?watermark_id=${data.watermark_id}`, data.download_filename)
        } catch {
          setResult({ ...data, download_error: 'The protected copy was created, but the browser download failed. Use Download again.' })
        }
      }
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

  const downloadCopy = async (downloadUrl = result?.download_url ?? (result?.document_id && result?.watermark_id ? `/api/documents/${result.document_id}/download?watermark_id=${result.watermark_id}` : undefined), filename = result?.download_filename ?? 'document') => {
    if (!downloadUrl) return
    const absoluteUrl = downloadUrl.startsWith('http') ? downloadUrl : `${API_BASE}${downloadUrl.replace(/^\/api/, '')}`
    const response = await axios.get(absoluteUrl, { responseType: 'blob' })
    const url = URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Decryption</Typography>

        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <Box sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2, p: 2 }}>
            <Typography variant="subtitle2" sx={{ color: whiteTheme.text, fontWeight: 700, mb: 1 }}>Recipient-secured download</Typography>
            <Typography variant="body2" sx={{ color: whiteTheme.subtext, lineHeight: 1.7 }}>
              Your authenticated recipient package is used automatically. No AES key is required or exposed in the browser.
            </Typography>
          </Box>

          <Autocomplete
            options={documents}
            value={documents.find((doc) => doc.document_id === selectedDocumentId) ?? null}
            getOptionLabel={(doc) => `${doc.original_filename} (${doc.document_id})`}
            onChange={(_, value) => setSelectedDocumentId(value?.document_id ?? '')}
            renderInput={(params) => <TextField {...params} label="Search encrypted documents" fullWidth />}
          />

          <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Recipient identity comes from the authenticated offline session.</Typography>

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
                    {result.download_error && <Typography variant="body2" sx={{ color: whiteTheme.warning }}>{result.download_error}</Typography>}
                    <Button variant="contained" onClick={() => void downloadCopy()} disabled={!result.watermark_id} sx={{ mt: 1, background: whiteTheme.primary, textTransform: 'none' }}>Download</Button>
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
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)
  const [status, setStatus] = useState('')
  const [open, setOpen] = useState(false)

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
      if (editingId) {
        await axios.patch(`${API_BASE}/recipients/${editingId}`, { name, department })
        setStatus(`Recipient updated: ${name}`)
      } else {
        await axios.post(`${API_BASE}/recipients`, { name, department, username: username || null, password: password || null })
        setStatus(username ? `Recipient and login created: ${username}` : `Recipient created: ${name}. Create a login from Admin Users.`)
      }
      setName('')
      setDepartment('')
      setUsername('')
      setPassword('')
      setEditingId(null)
      setOpen(false)
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
          <Button variant="contained" onClick={() => { setEditingId(null); setName(''); setDepartment(''); setUsername(''); setPassword(''); setOpen(true) }} sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>Add recipient</Button>
          {status && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>{status}</Typography>}

          <Box sx={{ display: 'grid', gap: 1 }}>
            {recipients.length === 0 ? <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No recipients found.</Typography> : recipients.map((recipient) => (
              <Card key={recipient.recipient_id} sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="subtitle1" sx={{ color: whiteTheme.text, fontWeight: 700 }}>{recipient.name}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>ID: {recipient.recipient_id}</Typography>
                  <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Department: {recipient.department}</Typography>
                  <Typography variant="body2" sx={{ color: recipient.active ? whiteTheme.success : whiteTheme.danger }}>{recipient.active ? 'Active' : 'Disabled'}</Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 1 }}><Button size="small" onClick={() => { setEditingId(recipient.recipient_id); setName(recipient.name); setDepartment(recipient.department); setOpen(true) }}>Edit</Button><Button size="small" color="warning" onClick={() => void axios.patch(`${API_BASE}/recipients/${recipient.recipient_id}`, { name: recipient.name, department: recipient.department, active: !recipient.active }).then(() => loadRecipients())}>Toggle status</Button><Button size="small" color="error" onClick={() => void axios.delete(`${API_BASE}/recipients/${recipient.recipient_id}`).then(() => loadRecipients())}>Disable</Button></Stack>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>
        <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm"><DialogTitle>{editingId ? 'Edit recipient' : 'Add recipient and login'}</DialogTitle><DialogContent dividers><Stack spacing={2} sx={{ pt: 1 }}><TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth /><TextField label="Department" value={department} onChange={(e) => setDepartment(e.target.value)} fullWidth />{!editingId && <><TextField label="Login username" value={username} onChange={(e) => setUsername(e.target.value)} fullWidth /><TextField label="Login password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} helperText="At least 8 characters" fullWidth /></>}</Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="contained" onClick={() => void handleCreate()}>{editingId ? 'Save changes' : 'Create recipient'}</Button></DialogActions></Dialog>
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

function EventsPage() {
  const [events, setEvents] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)
  const [verification, setVerification] = useState<any>(null)

  useEffect(() => { void axios.get(`${API_BASE}/events`).then(({ data }) => setEvents(data)).catch(() => setEvents([])) }, [])

  const inspect = async (event: any) => {
    setSelected(event)
    try {
      const { data } = await axios.post(`${API_BASE}/forensics/verify/${event.event_id}`)
      setVerification(data)
    } catch {
      setVerification({ valid: false, reason: 'Verification unavailable' })
    }
  }

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Decryption Events</Typography>
          {events.length === 0 ? <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>No signed decryption events recorded.</Typography> : events.map((event) => (
            <Box key={event.event_id} sx={{ display: 'flex', gap: 2, alignItems: 'center', justifyContent: 'space-between', borderBottom: `1px solid ${whiteTheme.line}`, py: 1.5, flexWrap: 'wrap' }}>
              <Box><Typography fontWeight={700}>{event.event_id}</Typography><Typography variant="body2" sx={{ color: whiteTheme.subtext }}>{event.recipient_id} · {event.document_id} · {event.watermark_id}</Typography></Box>
              <Button size="small" variant="outlined" onClick={() => void inspect(event)} sx={{ textTransform: 'none' }}>Verify event</Button>
            </Box>
          ))}
        </CardContent>
      </Card>
      {selected && <Card sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 3 }}><CardContent sx={{ p: 3 }}><Typography variant="h6" sx={{ color: whiteTheme.text }}>Event evidence</Typography><Stack spacing={0.75} sx={{ mt: 1.5 }}><Typography variant="body2">Event: {selected.event_id}</Typography><Typography variant="body2">Session: {selected.session_id}</Typography><Typography variant="body2">Watermark: {selected.watermark_id}</Typography><Typography variant="body2">Record hash: {selected.event_hash}</Typography><Typography variant="body2">Signature algorithm: {selected.signature_algorithm}</Typography><Typography variant="body2" sx={{ color: verification?.valid ? whiteTheme.success : whiteTheme.danger, fontWeight: 700 }}>Cryptographic verification: {verification?.valid ? 'VALID' : 'FAILED'}</Typography>{verification?.block && <Typography variant="body2">Ledger block: #{verification.block.block_number} · {verification.block.block_hash}</Typography>}</Stack></CardContent></Card>}
    </Box>
  )
}

function ForensicsPage() {
  const [eventId, setEventId] = useState('')
  const [evidence, setEvidence] = useState<File | null>(null)
  const [result, setResult] = useState<any>(null)
  const [recipientNames, setRecipientNames] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    void axios.get(`${API_BASE}/recipients`).then(({ data }) => {
      setRecipientNames(Object.fromEntries(data.map((recipient: any) => [recipient.recipient_id, recipient.name])))
    }).catch(() => setRecipientNames({}))
  }, [])

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

  const handleEvidence = async () => {
    if (!evidence) { setResult({ error: 'Choose a leaked file first.' }); return }
    setLoading(true)
    const form = new FormData()
    form.append('file', evidence)
    try { const { data } = await axios.post(`${API_BASE}/forensics/analyze-upload`, form); setResult(data) } catch (err: unknown) { setResult({ error: axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Analysis failed') : 'Analysis failed' }) } finally { setLoading(false) }
  }

  const downloadReport = async (caseId: string) => {
    const response = await axios.get(`${API_BASE}/forensics/cases/${caseId}/report.pdf`, { responseType: 'blob' })
    const url = URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    link.download = `TraceSeal-${caseId}.pdf`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Forensic Investigation</Typography>
        <Box sx={{ display: 'grid', gap: 2.5 }}>
          <Button variant="outlined" component="label" sx={{ textTransform: 'none' }}>Upload leaked document<input hidden type="file" onChange={(event) => setEvidence(event.target.files?.[0] ?? null)} /></Button>
          {evidence && <Typography variant="body2">Evidence: {evidence.name}</Typography>}
          <Button variant="contained" onClick={handleEvidence} disabled={loading} sx={{ background: whiteTheme.primary, textTransform: 'none' }}>Analyze uploaded evidence</Button>
          <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>LEAKED FILE -&gt; SHA3-256 -&gt; WATERMARK -&gt; LEDGER -&gt; SIGNED EVENT -&gt; RECIPIENT</Typography>
          <TextField label="Event ID" value={eventId} onChange={(e) => setEventId(e.target.value)} fullWidth />
          <Button variant="contained" onClick={handleLookup} disabled={loading} sx={{ background: whiteTheme.primary, borderRadius: 2, textTransform: 'none', fontWeight: 700 }}>{loading ? 'Loading...' : 'Lookup event'}</Button>

          {result && (
            <Card sx={{ background: whiteTheme.panelAlt, border: `1px solid ${whiteTheme.line}`, borderRadius: 2 }}>
              <CardContent sx={{ py: 2 }}>
                {result.error ? (
                  <Typography variant="body2" sx={{ color: whiteTheme.danger }}>{result.error}</Typography>
                ) : (
                  (() => {
                    const recipient = result.recipient ?? {}
                    const watermark = result.watermark ?? {}
                    const recipientId = result.recipient_id ?? recipient.recipient_id
                    const watermarkId = result.watermark_id ?? watermark.watermark_id
                    const recipientName = recipient.display_name ?? recipientNames[recipientId] ?? 'Name unavailable'
                    const isAnalysis = Boolean(result.watermark || result.attribution_confirmed !== undefined)
                    return (
                      <Box sx={{ display: 'grid', gap: 1 }}>
                        {isAnalysis && <Typography variant="h6" sx={{ color: result.attribution_confirmed ? whiteTheme.success : whiteTheme.danger, fontWeight: 800 }}>{result.verification_status ?? 'Verification result'}</Typography>}
                        <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Event ID: {result.event_id ?? 'Not found'}</Typography>
                        <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Recipient: {recipientName}{recipientId ? ` (${recipientId})` : ''}</Typography>
                        {result.document && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Document: {result.document.name ?? result.document.document_id}</Typography>}
                        <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Session: {result.session_id ?? 'See event record'}</Typography>
                        <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Watermark: {watermarkId ?? 'Not detected'}</Typography>
                        <Typography variant="body2" sx={{ color: result.watermark_valid ? whiteTheme.success : whiteTheme.danger }}>Watermark integrity: {result.watermark_valid ? 'VALID' : 'FAILED'}</Typography>
                        <Typography variant="body2" sx={{ color: result.signature_valid ? whiteTheme.success : whiteTheme.danger }}>ML-DSA signature: {result.signature_valid ? 'VALID' : 'FAILED'}</Typography>
                        {isAnalysis && <>
                          <Typography variant="body2" sx={{ color: result.ledger_match ? whiteTheme.success : whiteTheme.danger }}>Ledger match: {result.ledger_match ? 'PASS' : 'FAIL'}</Typography>
                          <Typography variant="body2" sx={{ color: result.chain_valid ? whiteTheme.success : whiteTheme.danger }}>Ledger chain: {result.chain_valid ? 'VALID' : 'INVALID'}</Typography>
                          <Typography variant="body2" sx={{ color: result.document_hash_match ? whiteTheme.success : whiteTheme.danger }}>Document record: {result.document_hash_match ? 'MATCH' : 'MISMATCH'}</Typography>
                          {result.block && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Block #{result.block.block_number} · Record hash {result.block.record_hash}</Typography>}
                          <Typography variant="body2" sx={{ color: result.attribution_confirmed ? whiteTheme.success : whiteTheme.danger, fontWeight: 700 }}>Attribution: {result.attribution_confirmed ? 'CONFIRMED' : 'NOT CONFIRMED'}</Typography>
                          {result.evidence_graph && <EvidenceGraph nodes={result.evidence_graph.nodes} />}
                          {result.timeline && <Box sx={{ mt: 2 }}><Typography variant="subtitle2" sx={{ mb: 1, color: whiteTheme.text }}>Evidence Timeline</Typography>{result.timeline.map((item: any) => <Box key={item.label} sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, borderBottom: `1px solid ${whiteTheme.line}`, py: 0.75 }}><Typography variant="body2">{item.label}</Typography><Typography variant="caption" sx={{ color: item.status === 'PASS' ? whiteTheme.success : whiteTheme.danger }}>{item.timestamp ?? 'Unavailable'}</Typography></Box>)}</Box>}
                          {result.case_id && <Button variant="outlined" onClick={() => void downloadReport(result.case_id)} sx={{ mt: 2, textTransform: 'none' }}>Download PDF evidence report</Button>}
                        </>}
                      </Box>
                    )
                  })()
                )}
              </CardContent>
            </Card>
          )}
        </Box>
      </CardContent>
    </Card>
  )
}

function CasesPage() {
  const [cases, setCases] = useState<any[]>([])
  useEffect(() => { void axios.get(`${API_BASE}/forensics/cases`).then(({ data }) => setCases(data)).catch(() => setCases([])) }, [])
  return <Card><CardContent><Typography variant="h5" sx={{ mb: 2 }}>Forensic Cases</Typography>{cases.length === 0 ? <Typography>No cases recorded.</Typography> : cases.map((item) => <Box key={item.case_id} sx={{ borderBottom: `1px solid ${whiteTheme.line}`, py: 1 }}><Typography fontWeight={700}>{item.case_id}</Typography><Typography variant="body2">{item.attribution_confirmed ? 'ATTRIBUTION CONFIRMED' : 'ATTRIBUTION NOT CONFIRMED'} | {item.evidence_filename ?? 'unknown evidence'}</Typography></Box>)}</CardContent></Card>
}

function ReportsPage() {
  const [cases, setCases] = useState<any[]>([])
  useEffect(() => { void axios.get(`${API_BASE}/forensics/cases`).then(({ data }) => setCases(data)).catch(() => setCases([])) }, [])
  const downloadReport = async (caseId: string) => {
    const response = await axios.get(`${API_BASE}/forensics/cases/${caseId}/report.pdf`, { responseType: 'blob' })
    const url = URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    link.download = `TraceSeal-${caseId}.pdf`
    link.click()
    URL.revokeObjectURL(url)
  }
  return <Card><CardContent><Typography variant="h5" sx={{ mb: 2 }}>Reports</Typography>{cases.length === 0 ? <Typography color="text.secondary">No forensic reports generated yet.</Typography> : cases.map((item) => <Box key={item.case_id} sx={{ display: 'flex', gap: 1, alignItems: 'center', borderBottom: `1px solid ${whiteTheme.line}`, py: 1 }}><Typography sx={{ flex: 1 }}>{item.case_id} · {item.attribution_confirmed ? 'Verified' : 'Not verified'}</Typography><Button variant="outlined" onClick={() => void downloadReport(item.case_id)} sx={{ textTransform: 'none' }}>Download PDF</Button></Box>)}</CardContent></Card>
}

function NotificationsPage({ user }: { user: AuthUser }) {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    const seen = JSON.parse(window.localStorage.getItem(`traceseal_seen_notifications_${user.user_id}`) ?? '[]') as string[]
    void axios.get(`${API_BASE}/notifications`).then(({ data }) => setItems((data.items ?? []).map((item: any) => ({ ...item, read: item.read || seen.includes(item.id) })))).catch(() => setItems([])).finally(() => setLoading(false))
  }, [user.user_id])
  const markSeen = () => {
    const ids = items.map((item) => item.id)
    window.localStorage.setItem(`traceseal_seen_notifications_${user.user_id}`, JSON.stringify(ids))
    setItems((current) => current.map((item) => ({ ...item, read: true })))
  }
  return <Card><CardContent><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}><Typography variant="h5">Notifications</Typography><Button variant="outlined" onClick={markSeen} disabled={items.every((item) => item.read)} sx={{ textTransform: 'none' }}>Mark all seen</Button></Box>{loading ? <Typography color="text.secondary">Loading notifications...</Typography> : items.length === 0 ? <Typography color="text.secondary">No document notifications yet.</Typography> : <Table size="small"><TableHead><TableRow><TableCell>Type</TableCell><TableCell>Document</TableCell><TableCell>Message</TableCell><TableCell>Status</TableCell><TableCell>Time</TableCell></TableRow></TableHead><TableBody>{items.map((item) => <TableRow key={item.id}><TableCell>{item.type}</TableCell><TableCell>{item.document_id}</TableCell><TableCell>{item.message}</TableCell><TableCell><Chip size="small" label={item.type === 'DOWNLOAD' ? 'DOWNLOADED' : item.read ? 'SEEN' : 'UNSEEN'} color={item.type === 'DOWNLOAD' ? 'success' : item.read ? 'default' : 'warning'} /></TableCell><TableCell>{item.timestamp ? new Date(item.timestamp).toLocaleString() : 'n/a'}</TableCell></TableRow>)}</TableBody></Table>}</CardContent></Card>
}

function SecurityPage() {
  const [status, setStatus] = useState<Record<string, any> | null>(null)
  useEffect(() => { void axios.get(`${API_BASE}/system/status`).then(({ data }) => setStatus(data)).catch(() => setStatus(null)) }, [])
  const checks = status ? [
    ['Authentication', 'READY', 'success'], ['Authorization', 'READY', 'success'], ['PQC backend', status.pqc, status.pqc === 'REAL LIBOQS' ? 'success' : 'warning'],
    ['ML-KEM', status.ml_kem ? 'REAL' : 'COMPATIBILITY', status.ml_kem ? 'success' : 'warning'], ['ML-DSA', status.ml_dsa ? 'REAL' : 'COMPATIBILITY', status.ml_dsa ? 'success' : 'warning'], ['Watermark engine', status.watermark_engine, 'success'], ['Ledger', status.ledger?.valid ? 'READY' : 'FAILED', status.ledger?.valid ? 'success' : 'error'],
    ['Database', status.database ? 'READY' : 'FAILED', status.database ? 'success' : 'error'], ['Storage', status.storage ? 'READY' : 'FAILED', status.storage ? 'success' : 'error'], ['Audit logging', status.audit_logging ? 'READY' : 'FAILED', status.audit_logging ? 'success' : 'error'],
  ] : []
  return <Card><CardContent><Typography variant="h5" sx={{ mb: 2 }}>Security Status Center</Typography><Typography variant="body2" sx={{ mb: 2 }}>Deployment: {status?.deployment ?? 'Loading...'}</Typography>{status?.pqc_reason && <Alert severity={status.pqc === 'REAL LIBOQS' ? 'success' : 'warning'} sx={{ mb: 2 }}>{status.pqc_reason}</Alert>}<Stack spacing={1}>{checks.map(([label, value, color]) => <Box key={String(label)} sx={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${whiteTheme.line}`, py: 1 }}><Typography>{String(label)}</Typography><Chip size="small" label={String(value)} color={color as 'success' | 'warning' | 'error'} /></Box>)}</Stack></CardContent></Card>
}

function SettingsPage() {
  const [status, setStatus] = useState<Record<string, any> | null>(null)
  useEffect(() => { void axios.get(`${API_BASE}/system/status`).then(({ data }) => setStatus(data)).catch(() => setStatus(null)) }, [])
  return <Card><CardContent><Typography variant="h5" sx={{ mb: 2 }}>System Settings</Typography><Stack spacing={1}><Typography variant="body2">Deployment: {status?.deployment ?? 'Loading...'}</Typography><Typography variant="body2">External KMS: NOT USED</Typography><Typography variant="body2">Public blockchain: NOT USED</Typography><Typography variant="body2">PQC backend: {status?.pqc ?? 'Loading...'}</Typography><Typography variant="body2">Ledger: {status?.ledger?.valid ? 'VALID' : 'UNAVAILABLE OR INVALID'}</Typography><Typography variant="body2">Storage: {status?.storage ? 'READY' : 'UNAVAILABLE'}</Typography></Stack></CardContent></Card>
}

function AdminUsersPage() {
  const [users, setUsers] = useState<any[]>([])
  const [recipients, setRecipients] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [recipientId, setRecipientId] = useState('')
  const [status, setStatus] = useState('')
  const [open, setOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<any | null>(null)

  const load = async () => {
    try {
      const [{ data: userData }, { data: recipientData }] = await Promise.all([
        axios.get(`${API_BASE}/admin/users`),
        axios.get(`${API_BASE}/recipients`),
      ])
      setUsers(userData)
      setRecipients(recipientData)
    } catch (err: unknown) {
      setStatus(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'Admin access required') : 'Admin access required')
    }
  }

  useEffect(() => { void load() }, [])

  const createUser = async () => {
    if (!username || !displayName || (!editingUser && !password)) {
      setStatus('Username, display name, and a password for new users are required.')
      return
    }
    try {
      const payload = { username, password: password || null, display_name: displayName, role: 'RECIPIENT', recipient_id: recipientId || null }
      if (editingUser) await axios.patch(`${API_BASE}/admin/users/${editingUser.user_id}/details`, payload)
      else await axios.post(`${API_BASE}/admin/users`, payload)
      setStatus(`${editingUser ? 'Updated' : 'Created'} login for ${displayName}.`)
      setUsername('')
      setPassword('')
      setDisplayName('')
      setRecipientId('')
      setOpen(false)
      setEditingUser(null)
      await load()
    } catch (err: unknown) {
      setStatus(axios.isAxiosError(err) ? String(err.response?.data?.detail ?? 'User creation failed') : 'User creation failed')
    }
  }

  return (
    <Card sx={{ background: whiteTheme.panel, border: `1px solid ${whiteTheme.line}`, boxShadow: whiteTheme.shadow, borderRadius: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ mb: 2, color: whiteTheme.text, fontWeight: 700 }}>Admin Users</Typography>
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>Create the recipient login after creating the recipient record. The password is chosen here by the administrator.</Typography>
          <Button variant="contained" onClick={() => { setEditingUser(null); setUsername(''); setPassword(''); setDisplayName(''); setRecipientId(''); setOpen(true) }} sx={{ background: whiteTheme.primary, textTransform: 'none' }}>Add user login</Button>
          {status && <Typography variant="body2" sx={{ color: whiteTheme.subtext }}>{status}</Typography>}
          {users.map((user) => <Box key={user.user_id} sx={{ borderTop: `1px solid ${whiteTheme.line}`, pt: 1 }}><Typography fontWeight={700}>{user.display_name}</Typography><Typography variant="body2">{user.username} | {user.role} | {user.recipient_id ?? 'not linked'} | {user.active ? 'active' : 'disabled'}</Typography><Button size="small" onClick={() => { setEditingUser(user); setUsername(user.username); setPassword(''); setDisplayName(user.display_name); setRecipientId(user.recipient_id ?? ''); setOpen(true) }}>Edit</Button><Button size="small" color={user.active ? 'warning' : 'success'} onClick={() => void axios.patch(`${API_BASE}/admin/users/${user.user_id}`, { active: !user.active }).then(() => load())}>{user.active ? 'Disable login' : 'Enable login'}</Button><Button size="small" color="error" onClick={() => void axios.delete(`${API_BASE}/admin/users/${user.user_id}`).then(() => load())}>Delete</Button></Box>)}
        </Stack>
        <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm"><DialogTitle>{editingUser ? 'Edit user login' : 'Create user login'}</DialogTitle><DialogContent dividers><Stack spacing={2} sx={{ pt: 1 }}><TextField label="Username" value={username} onChange={(event) => setUsername(event.target.value)} /><TextField label={editingUser ? 'New password (optional)' : 'Temporary password'} type="password" value={password} onChange={(event) => setPassword(event.target.value)} helperText="At least 8 characters." /><TextField label="Display name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /><TextField select SelectProps={{ native: true }} label="Link to recipient" value={recipientId} onChange={(event) => setRecipientId(event.target.value)}><option value="">Select recipient</option>{recipients.map((recipient) => <option key={recipient.recipient_id} value={recipient.recipient_id}>{recipient.name} ({recipient.recipient_id})</option>)}</TextField></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="contained" onClick={() => void createUser()}>{editingUser ? 'Save changes' : 'Create login'}</Button></DialogActions></Dialog>
      </CardContent>
    </Card>
  )
}

function App() {
  const [authenticated, setAuthenticated] = useState(Boolean(window.localStorage.getItem('traceseal_session')))
  const [user, setUser] = useState<AuthUser | null>(null)

  useEffect(() => {
    if (!authenticated) {
      setUser(null)
      return
    }
    void axios.get<AuthUser>(`${API_BASE}/auth/me`).then(({ data }) => setUser(data)).catch(() => {
      window.localStorage.removeItem('traceseal_session')
      setAuthenticated(false)
    })
  }, [authenticated])

  if (!authenticated) return <LoginPage onLogin={() => setAuthenticated(true)} />
  if (!user) return <Container sx={{ pt: 12 }}><Typography>Loading workspace...</Typography></Container>

  return (
    <BrowserRouter>
      <AppShell user={user} onLogout={() => { window.localStorage.removeItem('traceseal_session'); setAuthenticated(false) }}>
        <Container maxWidth={false} sx={{ px: 0 }}>
          <Routes>
            <Route path="/" element={<Dashboard user={user} />} />
            <Route path="/documents" element={<DocumentsPage />} />
            <Route path="/distribution" element={<DistributionPage />} />
            <Route path="/recipients" element={<RecipientsPage />} />
            <Route path="/decryption" element={<DecryptionPage />} />
            <Route path="/notifications" element={<NotificationsPage user={user} />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/watermarks" element={<WatermarkPage />} />
            <Route path="/ledger" element={<LedgerPage />} />
            <Route path="/forensics" element={<ForensicsPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/admin/users" element={<AdminUsersPage />} />
          </Routes>
        </Container>
      </AppShell>
    </BrowserRouter>
  )
}

export default App
