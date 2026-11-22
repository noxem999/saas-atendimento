const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const pino = require('pino');
const GroqModule = require('groq-sdk');
const Groq = GroqModule.default || GroqModule;
const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
} = require('@whiskeysockets/baileys');

const app = express();
const PORT = process.env.PORT || 3000;

// O segredo do JWT vem da variável de ambiente JWT_SECRET.
// O fallback existe só para desenvolvimento local: em produção o servidor se recusa a subir sem ele.
const EM_PRODUCAO = process.env.NODE_ENV === 'production';
if (EM_PRODUCAO && !process.env.JWT_SECRET) {
  console.error('ERRO: defina a variável de ambiente JWT_SECRET antes de subir em produção.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'segredo-apenas-para-desenvolvimento';
const SALT_ROUNDS = 10;

app.use(express.json());

// "Banco de dados" simulado em memória (zera quando o servidor reinicia)
const usuarios = [];
let proximoId = 1;

const emailValido = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const normalizarEmail = (email) => String(email).trim().toLowerCase();

// ---------- Middleware de autenticação ----------
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [tipo, token] = header.split(' ');

  if (tipo !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Token não informado.' });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    const mensagem =
      err.name === 'TokenExpiredError' ? 'Sessão expirada. Entre novamente.' : 'Token inválido.';
    return res.status(401).json({ erro: mensagem });
  }
}

// ---------- Rotas ----------
// Health check (use em Settings > Health Check Path no Render)
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/registrar', async (req, res) => {
  try {
    const { nome, email, senha } = req.body || {};

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Preencha nome, e-mail e senha.' });
    }
    if (!emailValido(String(email).trim())) {
      return res.status(400).json({ erro: 'Informe um e-mail válido.' });
    }
    if (String(senha).length < 6) {
      return res.status(400).json({ erro: 'A senha precisa ter pelo menos 6 caracteres.' });
    }

    const emailNormalizado = normalizarEmail(email);
    if (usuarios.some((u) => u.email === emailNormalizado)) {
      return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(String(senha), SALT_ROUNDS);
    const usuario = {
      id: proximoId++,
      nome: String(nome).trim(),
      email: emailNormalizado,
      senhaHash,
      criadoEm: new Date().toISOString(),
    };
    usuarios.push(usuario);

    return res.status(201).json({ mensagem: 'Conta criada com sucesso.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao registrar.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    if (!email || !senha) {
      return res.status(400).json({ erro: 'Informe e-mail e senha.' });
    }

    const usuario = usuarios.find((u) => u.email === normalizarEmail(email));
    // Mesma mensagem para e-mail inexistente e senha errada (evita revelar quais e-mails existem)
    const senhaCorreta = usuario ? await bcrypt.compare(String(senha), usuario.senhaHash) : false;

    if (!usuario || !senhaCorreta) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const token = jwt.sign({ sub: usuario.id, email: usuario.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.json({ token, nome: usuario.nome });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao entrar.' });
  }
});

app.get('/api/painel', autenticar, (req, res) => {
  const usuario = usuarios.find((u) => u.id === req.auth.sub);
  if (!usuario) {
    return res.status(401).json({ erro: 'Usuário não encontrado. Entre novamente.' });
  }

  return res.json({
    id: usuario.id,
    nome: usuario.nome,
    email: usuario.email,
    criadoEm: usuario.criadoEm,
  });
});

// ---------- Agendamentos (dados simulados em memória) ----------
const agendamentos = [
  { id: 1, cliente: 'João', servico: 'Corte', horario: '14:00' },
  { id: 2, cliente: 'Maria', servico: 'Escova', horario: '15:30' },
  { id: 3, cliente: 'Carlos', servico: 'Barba', horario: '16:45' },
];

app.get('/api/agendamentos', autenticar, (req, res) => {
  res.json(agendamentos);
});

// ---------- Robô de atendimento (IA / Groq) ----------
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const SYSTEM_PROMPT =
  process.env.BOT_SYSTEM_PROMPT ||
  'Você é um atendente virtual educado. Responda de forma curta, clara e em português do Brasil.';

// Sem a chave, o servidor funciona normalmente, só que o robô fica desligado.
const groq = GROQ_API_KEY ? new Groq({ apiKey: GROQ_API_KEY }) : null;
if (!groq) {
  console.warn('AVISO: GROQ_API_KEY não definida. O robô de atendimento está desligado.');
} else {
  console.log(`Robô de atendimento LIGADO (modelo: ${GROQ_MODEL}).`);
}

// Histórico curto por cliente (em memória) para a IA entender o contexto da conversa
const historicos = new Map();
const MAX_MENSAGENS_HISTORICO = 10;
const MAX_CONVERSAS_EM_MEMORIA = 500;

async function gerarRespostaIA(jid, textoCliente) {
  const historico = historicos.get(jid) || [];
  historico.push({ role: 'user', content: textoCliente });
  while (historico.length > MAX_MENSAGENS_HISTORICO) historico.shift();

  try {
    const completion = await groq.chat.completions.create({
      model: GROQ_MODEL,
      messages: [{ role: 'system', content: SYSTEM_PROMPT }, ...historico],
      temperature: 0.6,
      max_tokens: 300,
    });

    const resposta = completion.choices?.[0]?.message?.content?.trim();
    if (resposta) {
      historico.push({ role: 'assistant', content: resposta });
      while (historico.length > MAX_MENSAGENS_HISTORICO) historico.shift();
    }

    // Evita crescer sem limite: descarta a conversa mais antiga
    if (!historicos.has(jid) && historicos.size >= MAX_CONVERSAS_EM_MEMORIA) {
      historicos.delete(historicos.keys().next().value);
    }
    historicos.set(jid, historico);

    return resposta;
  } catch (err) {
    historico.pop(); // remove a pergunta que ficou sem resposta
    throw err;
  }
}

// ---------- WhatsApp (Baileys) ----------
// Sessão do WhatsApp (não versionar!). No Render, aponte WHATSAPP_AUTH_DIR para um disco persistente
// (ex.: /data/auth_whatsapp); sem isso a sessão se perde a cada deploy/reinício.
const AUTH_DIR = process.env.WHATSAPP_AUTH_DIR || path.join(__dirname, 'auth_whatsapp');

let qrCodeAtual = null; // QR Code atual em Base64 (PNG, sem o prefixo "data:...")
let whatsappConectado = false;
let iniciandoWhatsApp = false;

async function iniciarWhatsApp() {
  if (iniciandoWhatsApp) return; // evita abrir duas conexões ao mesmo tempo
  iniciandoWhatsApp = true;

  try {
    const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version,
      auth: state,
      logger: pino({ level: 'silent' }),
      browser: ['Painel SaaS', 'Chrome', '1.0.0'],
    });

    sock.ev.on('creds.update', saveCreds);

    // Mensagens recebidas: responde com a IA
    sock.ev.on('messages.upsert', async ({ messages, type }) => {
      console.log(`[bot] messages.upsert recebido (type=${type}, qtd=${messages.length})`);

      if (type !== 'notify') {
        console.log(`[bot] ignorado: type "${type}" (só respondo "notify")`);
        return;
      }
      if (!groq) {
        console.log('[bot] ignorado: GROQ_API_KEY não está definida, o robô está desligado.');
        return;
      }

      for (const msg of messages) {
        try {
          const jid = msg.key?.remoteJid;

          if (!msg.message) {
            console.log(`[bot] ignorado (${jid}): mensagem sem conteúdo (pode estar descriptografando).`);
            continue;
          }
          if (msg.key.fromMe) {
            console.log(`[bot] ignorado (${jid}): mensagem enviada por mim mesmo (fromMe).`);
            continue;
          }
          if (!jid || jid.endsWith('@g.us') || jid.endsWith('@broadcast')) {
            console.log(`[bot] ignorado (${jid}): grupo ou status.`);
            continue;
          }

          // Ignora mensagens antigas (acumuladas enquanto o servidor estava fora do ar)
          const ts = Number(msg.messageTimestamp?.toNumber?.() ?? msg.messageTimestamp ?? 0);
          if (ts > 0 && Date.now() / 1000 - ts > 300) {
            console.log(`[bot] ignorado (${jid}): mensagem antiga.`);
            continue;
          }

          // Desembrulha mensagens temporárias / de visualização única
          const conteudo =
            msg.message.ephemeralMessage?.message ||
            msg.message.viewOnceMessage?.message ||
            msg.message.viewOnceMessageV2?.message ||
            msg.message.documentWithCaptionMessage?.message ||
            msg.message;

          // Só mensagens de texto
          const texto = conteudo.conversation || conteudo.extendedTextMessage?.text;
          if (!texto || !texto.trim()) {
            console.log(`[bot] ignorado (${jid}): não é texto (tipos: ${Object.keys(conteudo).join(', ')}).`);
            continue;
          }

          console.log(`[bot] mensagem de ${jid}: "${texto.trim().slice(0, 80)}"`);

          await sock.sendPresenceUpdate('composing', jid); // "digitando..."
          const resposta = await gerarRespostaIA(jid, texto.trim());
          await sock.sendPresenceUpdate('paused', jid);

          if (!resposta) {
            console.log('[bot] a IA retornou uma resposta vazia.');
            continue;
          }

          await sock.sendMessage(jid, { text: resposta });
          console.log(`[bot] resposta enviada para ${jid}.`);
        } catch (err) {
          console.error(
            `[bot] ERRO ao responder (status=${err.status ?? 'n/a'}): ${err.message}`
          );
        }
      }
    });

    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect, qr } = update;

      // Novo QR Code: converte para imagem e guarda na variável global
      if (qr) {
        try {
          const dataUrl = await QRCode.toDataURL(qr, { width: 300, margin: 2 });
          qrCodeAtual = dataUrl.split(',')[1]; // só o Base64
        } catch (err) {
          console.error('Erro ao gerar QR Code:', err.message);
        }
      }

      if (connection === 'open') {
        whatsappConectado = true;
        qrCodeAtual = null;
        console.log('WhatsApp conectado.');
      }

      if (connection === 'close') {
        whatsappConectado = false;
        qrCodeAtual = null;

        const status = lastDisconnect?.error?.output?.statusCode;
        if (status === DisconnectReason.loggedOut) {
          // Aparelho desconectado pelo celular: apaga a sessão para gerar um QR novo
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
          console.log('WhatsApp desconectado pelo aparelho. Gerando novo QR Code...');
        } else {
          console.log(`Conexão do WhatsApp fechada (código ${status}). Reconectando...`);
        }

        iniciandoWhatsApp = false;
        setTimeout(iniciarWhatsApp, 3000);
      }
    });
  } catch (err) {
    console.error('Erro ao iniciar o WhatsApp:', err.message);
    iniciandoWhatsApp = false;
    setTimeout(iniciarWhatsApp, 5000);
  }
}

app.get('/api/whatsapp/qrcode', autenticar, (req, res) => {
  if (whatsappConectado) {
    return res.json({ conectado: true });
  }
  return res.json({ qrcode: qrCodeAtual, conectado: false });
});

// ---------- Front-end ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  iniciarWhatsApp();
});