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

app.set('trust proxy', 1); // o Render fica atrás de um proxy: necessário para ver o IP real
app.use(express.json({ limit: '100kb' }));

// ===================================================================
// Armazenamento (arquivo JSON)
// ===================================================================
// No Render, aponte DATA_DIR para um disco persistente (ex.: /data).
// Sem isso, contas, agendamentos e sessões do WhatsApp somem a cada deploy/reinício.
const DATA_DIR = process.env.DATA_DIR || __dirname;
const ARQUIVO_DADOS = path.join(DATA_DIR, 'dados.json');
const FUSO = 'America/Sao_Paulo';

function carregarDados() {
  try {
    const dados = JSON.parse(fs.readFileSync(ARQUIVO_DADOS, 'utf8'));
    return {
      usuarios: Array.isArray(dados.usuarios) ? dados.usuarios : [],
      agendamentos: Array.isArray(dados.agendamentos) ? dados.agendamentos : [],
    };
  } catch {
    return { usuarios: [], agendamentos: [] };
  }
}

const db = carregarDados();
let proximoUsuarioId = db.usuarios.reduce((m, u) => Math.max(m, u.id || 0), 0) + 1;
let proximoAgendamentoId = db.agendamentos.reduce((m, a) => Math.max(m, a.id || 0), 0) + 1;

function salvarDados() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const temporario = `${ARQUIVO_DADOS}.tmp`;
    fs.writeFileSync(temporario, JSON.stringify(db, null, 2));
    fs.renameSync(temporario, ARQUIVO_DADOS); // troca atômica: evita arquivo corrompido
  } catch (err) {
    console.error('Erro ao salvar os dados:', err.message);
  }
}

const emailValido = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const normalizarEmail = (email) => String(email).trim().toLowerCase();
const buscarUsuario = (id) => db.usuarios.find((u) => u.id === id);

// ===================================================================
// Proteção contra excesso de tentativas (login e cadastro)
// ===================================================================
const tentativas = new Map();
const JANELA_MS = 15 * 60 * 1000;
const MAX_TENTATIVAS = 30;

function limitarTentativas(req, res, next) {
  const agora = Date.now();
  let registro = tentativas.get(req.ip);
  if (!registro || registro.expira < agora) {
    registro = { total: 0, expira: agora + JANELA_MS };
  }
  registro.total += 1;
  tentativas.set(req.ip, registro);

  if (registro.total > MAX_TENTATIVAS) {
    return res.status(429).json({ erro: 'Muitas tentativas. Aguarde alguns minutos e tente de novo.' });
  }
  next();
}
setInterval(() => {
  const agora = Date.now();
  for (const [ip, registro] of tentativas) if (registro.expira < agora) tentativas.delete(ip);
}, 10 * 60 * 1000).unref();

// ===================================================================
// Autenticação
// ===================================================================
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [tipo, token] = header.split(' ');

  if (tipo !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Token não informado.' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    const mensagem =
      err.name === 'TokenExpiredError' ? 'Sessão expirada. Entre novamente.' : 'Token inválido.';
    return res.status(401).json({ erro: mensagem });
  }

  const usuario = buscarUsuario(payload.sub);
  if (!usuario) {
    return res.status(401).json({ erro: 'Usuário não encontrado. Entre novamente.' });
  }
  if (!usuario.ativo) {
    return res.status(403).json({ erro: 'Sua conta está bloqueada. Entre em contato com o suporte.' });
  }

  req.usuario = usuario;
  next();
}

function somenteAdmin(req, res, next) {
  if (req.usuario.role !== 'admin') {
    return res.status(403).json({ erro: 'Acesso restrito ao administrador.' });
  }
  next();
}

// Cria (ou atualiza) a conta de administrador a partir das variáveis de ambiente.
// Assim ninguém consegue "tomar" o e-mail do admin cadastrando-se antes dele.
async function garantirAdmin() {
  const email = process.env.ADMIN_EMAIL ? normalizarEmail(process.env.ADMIN_EMAIL) : '';
  const senha = process.env.ADMIN_SENHA || '';

  if (!email || senha.length < 6) {
    console.warn('AVISO: defina ADMIN_EMAIL e ADMIN_SENHA (mín. 6 caracteres) para ter um administrador.');
    return;
  }

  let admin = db.usuarios.find((u) => u.email === email);
  if (!admin) {
    admin = {
      id: proximoUsuarioId++,
      nome: process.env.ADMIN_NOME || 'Administrador',
      email,
      senhaHash: await bcrypt.hash(senha, SALT_ROUNDS),
      role: 'admin',
      ativo: true,
      empresa: { nome: '', info: '' },
      criadoEm: new Date().toISOString(),
      ultimoLoginEm: null,
    };
    db.usuarios.push(admin);
  } else {
    admin.role = 'admin';
    admin.ativo = true;
    if (!(await bcrypt.compare(senha, admin.senhaHash))) {
      admin.senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
    }
  }
  salvarDados();
  console.log(`Administrador pronto: ${email}`);
}

// ===================================================================
// Rotas de conta
// ===================================================================
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/registrar', limitarTentativas, async (req, res) => {
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
    if (db.usuarios.some((u) => u.email === emailNormalizado)) {
      return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    db.usuarios.push({
      id: proximoUsuarioId++,
      nome: String(nome).trim().slice(0, 80),
      email: emailNormalizado,
      senhaHash: await bcrypt.hash(String(senha), SALT_ROUNDS),
      role: 'cliente',
      ativo: true,
      empresa: { nome: '', info: '' },
      criadoEm: new Date().toISOString(),
      ultimoLoginEm: null,
    });
    salvarDados();

    return res.status(201).json({ mensagem: 'Conta criada com sucesso.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao registrar.' });
  }
});

app.post('/api/login', limitarTentativas, async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    if (!email || !senha) {
      return res.status(400).json({ erro: 'Informe e-mail e senha.' });
    }

    const usuario = db.usuarios.find((u) => u.email === normalizarEmail(email));
    // Mesma mensagem para e-mail inexistente e senha errada (não revela quais e-mails existem)
    const senhaCorreta = usuario ? await bcrypt.compare(String(senha), usuario.senhaHash) : false;

    if (!usuario || !senhaCorreta) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }
    if (!usuario.ativo) {
      return res.status(403).json({ erro: 'Sua conta está bloqueada. Entre em contato com o suporte.' });
    }

    usuario.ultimoLoginEm = new Date().toISOString();
    salvarDados();

    const token = jwt.sign({ sub: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token, nome: usuario.nome, role: usuario.role });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao entrar.' });
  }
});

app.get('/api/painel', autenticar, (req, res) => {
  const { id, nome, email, role, criadoEm } = req.usuario;
  res.json({ id, nome, email, role, criadoEm });
});

// Dados da empresa do cliente (usados pela IA no atendimento)
app.get('/api/configuracao', autenticar, (req, res) => {
  const empresa = req.usuario.empresa || {};
  res.json({ nome: empresa.nome || '', info: empresa.info || '' });
});

app.put('/api/configuracao', autenticar, (req, res) => {
  const { nome, info } = req.body || {};
  req.usuario.empresa = {
    nome: String(nome || '').trim().slice(0, 100),
    info: String(info || '').trim().slice(0, 3000),
  };
  salvarDados();
  res.json({ mensagem: 'Configuração salva.', ...req.usuario.empresa });
});

// ===================================================================
// Agendamentos (cada cliente só enxerga os seus)
// ===================================================================
function agoraNoBrasil() {
  const agora = new Date();
  return {
    data: agora.toLocaleDateString('en-CA', { timeZone: FUSO }), // AAAA-MM-DD
    hora: agora.toLocaleTimeString('pt-BR', { timeZone: FUSO, hour: '2-digit', minute: '2-digit', hour12: false }),
    diaSemana: agora.toLocaleDateString('pt-BR', { timeZone: FUSO, weekday: 'long' }),
  };
}

const dataParaBR = (iso) => iso.split('-').reverse().join('/');

function criarAgendamento(usuario, jid, dados) {
  const cliente = String(dados?.nome || '').trim().slice(0, 80);
  const servico = String(dados?.servico || '').trim().slice(0, 80);
  const data = String(dados?.data || '').trim();
  const horario = String(dados?.horario || '').trim();

  const dataValida =
    /^\d{4}-\d{2}-\d{2}$/.test(data) && new Date(`${data}T00:00:00Z`).toISOString().slice(0, 10) === data;
  const horarioValido = /^([01]\d|2[0-3]):[0-5]\d$/.test(horario);

  if (!cliente || !servico || !dataValida || !horarioValido) {
    return { ok: false, motivo: 'invalido' };
  }

  const agora = agoraNoBrasil();
  if (data < agora.data || (data === agora.data && horario <= agora.hora)) {
    return { ok: false, motivo: 'passado' };
  }

  if (db.agendamentos.some((a) => a.usuarioId === usuario.id && a.data === data && a.horario === horario)) {
    return { ok: false, motivo: 'ocupado' };
  }

  const agendamento = {
    id: proximoAgendamentoId++,
    usuarioId: usuario.id,
    cliente,
    servico,
    data,
    horario,
    contato: jid && jid.endsWith('@s.whatsapp.net') ? jid.split('@')[0] : null,
    jid: jid || null, // uso interno: o bot usa para lembrar dos agendamentos de cada pessoa
    criadoEm: new Date().toISOString(),
  };
  db.agendamentos.push(agendamento);
  salvarDados();
  return { ok: true, agendamento };
}

app.get('/api/agendamentos', autenticar, (req, res) => {
  const lista = db.agendamentos
    .filter((a) => a.usuarioId === req.usuario.id)
    .sort((a, b) => `${a.data} ${a.horario}`.localeCompare(`${b.data} ${b.horario}`))
    .map(({ jid, usuarioId, ...publico }) => publico); // dados internos não vão para o painel
  res.json(lista);
});

// ===================================================================
// Robô de atendimento (IA / Groq)
// ===================================================================
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

// Sem a chave, o servidor funciona normalmente, só que o robô fica desligado.
const groq = GROQ_API_KEY ? new Groq({ apiKey: GROQ_API_KEY }) : null;
if (!groq) {
  console.warn('AVISO: GROQ_API_KEY não definida. O robô de atendimento está desligado.');
} else {
  console.log(`Robô de atendimento LIGADO (modelo: ${GROQ_MODEL}).`);
}

// Prompt GLOBAL: serve para qualquer empresa. Os dados de cada cliente vêm da aba "Minha empresa".
// Se quiser trocar a personalidade de todos de uma vez, defina BOT_SYSTEM_PROMPT.
const PROMPT_BASE =
  process.env.BOT_SYSTEM_PROMPT ||
  `Você é o atendente virtual da empresa, atendendo clientes pelo WhatsApp.
- Seja educado, simpático e objetivo. Escreva em português do Brasil, com mensagens curtas (no máximo 3 frases).
- Ajude o cliente a tirar dúvidas sobre a empresa e a marcar horário.
- Use SOMENTE as informações da empresa fornecidas abaixo. Se não souber algo (preço, endereço, prazo, disponibilidade), diga que vai confirmar com a equipe. Nunca invente.
- Não converse sobre assuntos que não tenham relação com o atendimento da empresa.`;

const PROTOCOLO_AGENDAMENTO = `AGENDAMENTOS:
Para marcar um horário você precisa de 4 dados: nome do cliente, serviço, data e horário. Peça o que estiver faltando, de forma curta.
Quando tiver os 4 dados e o cliente tiver confirmado, escreva sua mensagem de confirmação normalmente e, no FINAL dela, acrescente uma linha exatamente neste formato (o cliente não vê essa linha):
[[AGENDAR {"nome":"Nome do cliente","servico":"Serviço","data":"AAAA-MM-DD","horario":"HH:MM"}]]
Regras:
- Nunca use essa linha antes da confirmação do cliente e nunca com dados inventados ou incompletos.
- Use apenas datas e horários futuros. Converta expressões como "amanhã" ou "sexta" para a data real usando a data de hoje informada abaixo.
- Não ofereça horários que estejam na lista de horários ocupados.
- Para cancelar ou alterar um agendamento, diga ao cliente que você vai avisar a equipe para confirmar.
- Se o cliente perguntar sobre os horários dele, responda com base nos "agendamentos deste cliente" abaixo.`;

// Monta o prompt completo de cada conversa, com os dados da empresa, a data de hoje e os agendamentos
function construirSystemPrompt(usuario, jid) {
  const agora = agoraNoBrasil();
  const empresa = usuario.empresa || {};
  const partes = [PROMPT_BASE];

  if (empresa.nome) partes.push(`Nome da empresa: ${empresa.nome}`);
  if (empresa.info) {
    partes.push(`Informações da empresa (serviços, preços, horário de funcionamento, endereço):\n${empresa.info}`);
  }

  partes.push(PROTOCOLO_AGENDAMENTO);
  partes.push(`Hoje é ${agora.diaSemana}, ${dataParaBR(agora.data)} (${agora.data}). Agora são ${agora.hora} (horário de Brasília).`);

  const futuros = db.agendamentos.filter((a) => a.usuarioId === usuario.id && a.data >= agora.data);

  const doCliente = futuros.filter((a) => a.jid === jid);
  partes.push(
    doCliente.length
      ? `Agendamentos deste cliente:\n${doCliente
          .map((a) => `- ${dataParaBR(a.data)} às ${a.horario}: ${a.servico} (em nome de ${a.cliente})`)
          .join('\n')}`
      : 'Agendamentos deste cliente: nenhum.'
  );

  // Só data e horário: não revelamos o nome de outras pessoas
  const ocupados = futuros.slice(0, 80).map((a) => `${dataParaBR(a.data)} às ${a.horario}`);
  partes.push(`Horários já ocupados (não oferecer): ${ocupados.length ? ocupados.join('; ') : 'nenhum.'}`);

  return partes.join('\n\n');
}

// Procura o comando de agendamento na resposta da IA, registra no painel e limpa o texto
const REGEX_AGENDAR = /\[\[\s*AGENDAR\s*(\{[\s\S]*?\})\s*\]\]/;
const REGEX_AGENDAR_QUALQUER = /\[\[\s*AGENDAR[\s\S]*?\]\]/g;

function processarAgendamentoDaResposta(usuario, jid, resposta) {
  const texto = resposta.replace(REGEX_AGENDAR_QUALQUER, '').trim();
  const achado = resposta.match(REGEX_AGENDAR);
  if (!achado) return texto;

  let dados;
  try {
    dados = JSON.parse(achado[1]);
  } catch {
    console.log('[bot] comando de agendamento com JSON inválido.');
    return texto;
  }

  const resultado = criarAgendamento(usuario, jid, dados);

  if (resultado.ok) {
    const a = resultado.agendamento;
    console.log(`[bot] (cliente ${usuario.id}) agendamento #${a.id} criado: ${a.cliente}, ${a.servico}, ${a.data} ${a.horario}`);
    return texto || `Agendamento confirmado: ${a.servico} em ${dataParaBR(a.data)} às ${a.horario}, no nome de ${a.cliente}.`;
  }

  console.log(`[bot] (cliente ${usuario.id}) agendamento recusado (${resultado.motivo}).`);
  if (resultado.motivo === 'ocupado') {
    return 'Poxa, esse horário acabou de ser ocupado. Pode escolher outro horário?';
  }
  if (resultado.motivo === 'passado') {
    return 'Esse horário já passou. Pode me passar uma data e um horário futuros?';
  }
  return 'Não consegui registrar o agendamento. Pode me confirmar nome, serviço, data e horário?';
}

// Histórico curto por conversa (em memória), separado por cliente do sistema
const historicos = new Map();
const MAX_MENSAGENS_HISTORICO = 10;
const MAX_CONVERSAS_EM_MEMORIA = 2000;

async function gerarRespostaIA(usuario, jid, textoCliente) {
  const chave = `${usuario.id}:${jid}`;
  const historico = historicos.get(chave) || [];
  historico.push({ role: 'user', content: textoCliente });
  while (historico.length > MAX_MENSAGENS_HISTORICO) historico.shift();

  try {
    const completion = await groq.chat.completions.create({
      model: GROQ_MODEL,
      messages: [{ role: 'system', content: construirSystemPrompt(usuario, jid) }, ...historico],
      temperature: 0.5,
      max_tokens: 400,
    });

    const respostaBruta = completion.choices?.[0]?.message?.content?.trim() || '';
    const resposta = respostaBruta ? processarAgendamentoDaResposta(usuario, jid, respostaBruta) : '';
    if (resposta) {
      historico.push({ role: 'assistant', content: resposta });
      while (historico.length > MAX_MENSAGENS_HISTORICO) historico.shift();
    }

    // Evita crescer sem limite: descarta a conversa mais antiga
    if (!historicos.has(chave) && historicos.size >= MAX_CONVERSAS_EM_MEMORIA) {
      historicos.delete(historicos.keys().next().value);
    }
    historicos.set(chave, historico);

    return resposta;
  } catch (err) {
    historico.pop(); // remove a pergunta que ficou sem resposta
    throw err;
  }
}

// ===================================================================
// WhatsApp (Baileys): uma sessão por cliente do sistema
// ===================================================================
// Cada cliente tem a própria pasta de autenticação e o próprio QR Code.
const AUTH_ROOT = process.env.WHATSAPP_AUTH_DIR || path.join(DATA_DIR, 'auth_whatsapp');
const MAX_SESSOES = Number(process.env.MAX_SESSOES) || 20; // cada sessão consome memória
const sessoes = new Map(); // usuarioId -> { sock, qr, conectado, iniciando, parar }
let versaoBaileys = null;

const dirSessao = (usuarioId) => path.join(AUTH_ROOT, `usuario-${usuarioId}`);
const temCredenciais = (usuarioId) => fs.existsSync(path.join(dirSessao(usuarioId), 'creds.json'));

async function tratarMensagens(usuarioId, sock, { messages, type }) {
  const usuario = buscarUsuario(usuarioId);
  if (!usuario || !usuario.ativo) return;

  console.log(`[bot ${usuarioId}] messages.upsert (type=${type}, qtd=${messages.length})`);
  if (type !== 'notify') return;
  if (!groq) {
    console.log(`[bot ${usuarioId}] ignorado: GROQ_API_KEY não está definida.`);
    return;
  }

  for (const msg of messages) {
    try {
      const jid = msg.key?.remoteJid;

      if (!msg.message) continue;
      if (msg.key.fromMe) continue; // enviada por você mesmo
      if (!jid || jid.endsWith('@g.us') || jid.endsWith('@broadcast')) continue; // grupos e status

      // Ignora mensagens antigas (acumuladas enquanto o servidor estava fora do ar)
      const ts = Number(msg.messageTimestamp?.toNumber?.() ?? msg.messageTimestamp ?? 0);
      if (ts > 0 && Date.now() / 1000 - ts > 300) continue;

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
        console.log(`[bot ${usuarioId}] ignorado (${jid}): não é texto (${Object.keys(conteudo).join(', ')}).`);
        continue;
      }

      console.log(`[bot ${usuarioId}] mensagem de ${jid}: "${texto.trim().slice(0, 80)}"`);

      await sock.sendPresenceUpdate('composing', jid); // "digitando..."
      const resposta = await gerarRespostaIA(usuario, jid, texto.trim());
      await sock.sendPresenceUpdate('paused', jid);

      if (!resposta) {
        console.log(`[bot ${usuarioId}] a IA retornou uma resposta vazia.`);
        continue;
      }

      await sock.sendMessage(jid, { text: resposta });
      console.log(`[bot ${usuarioId}] resposta enviada para ${jid}.`);
    } catch (err) {
      console.error(`[bot ${usuarioId}] ERRO ao responder (status=${err.status ?? 'n/a'}): ${err.message}`);
    }
  }
}

async function iniciarSessao(usuarioId) {
  let s = sessoes.get(usuarioId);
  if (s?.iniciando) return; // já está abrindo/aberta
  if (!s) {
    s = { sock: null, qr: null, conectado: false, iniciando: false, parar: false };
    sessoes.set(usuarioId, s);
  }
  s.iniciando = true;
  s.parar = false;

  try {
    const { state, saveCreds } = await useMultiFileAuthState(dirSessao(usuarioId));

    if (!versaoBaileys) {
      try {
        versaoBaileys = (await fetchLatestBaileysVersion()).version;
      } catch {
        /* usa a versão padrão da biblioteca */
      }
    }

    const sock = makeWASocket({
      ...(versaoBaileys ? { version: versaoBaileys } : {}),
      auth: state,
      logger: pino({ level: 'silent' }),
      browser: ['Painel SaaS', 'Chrome', '1.0.0'],
    });
    s.sock = sock;

    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('messages.upsert', (evento) => tratarMensagens(usuarioId, sock, evento));

    sock.ev.on('connection.update', async (update) => {
      if (sessoes.get(usuarioId) !== s) return; // evento de uma sessão antiga
      const { connection, lastDisconnect, qr } = update;

      // Novo QR Code: converte para imagem e guarda na sessão deste cliente
      if (qr) {
        try {
          const dataUrl = await QRCode.toDataURL(qr, { width: 300, margin: 2 });
          s.qr = dataUrl.split(',')[1]; // só o Base64
        } catch (err) {
          console.error(`[wa ${usuarioId}] erro ao gerar QR Code:`, err.message);
        }
      }

      if (connection === 'open') {
        s.conectado = true;
        s.qr = null;
        console.log(`[wa ${usuarioId}] WhatsApp conectado.`);
      }

      if (connection === 'close') {
        s.conectado = false;
        s.qr = null;
        s.iniciando = false;

        if (s.parar) return; // encerrada de propósito (bloqueio, exclusão ou desconexão)

        const status = lastDisconnect?.error?.output?.statusCode;

        if (status === DisconnectReason.loggedOut) {
          // Aparelho removido pelo celular: apaga a sessão. Um novo QR só sai se o cliente pedir.
          console.log(`[wa ${usuarioId}] desconectado pelo aparelho.`);
          sessoes.delete(usuarioId);
          fs.rmSync(dirSessao(usuarioId), { recursive: true, force: true });
          return;
        }

        if (status === DisconnectReason.connectionReplaced) {
          // A mesma conta foi aberta em outro lugar: não brigar pela conexão
          console.log(`[wa ${usuarioId}] conexão substituída por outro dispositivo/servidor.`);
          sessoes.delete(usuarioId);
          return;
        }

        if (!state.creds.me) {
          // Nunca chegou a ser pareado (QR expirou sem leitura): não fica gerando QR sem ninguém olhando
          console.log(`[wa ${usuarioId}] QR expirou sem leitura.`);
          sessoes.delete(usuarioId);
          return;
        }

        console.log(`[wa ${usuarioId}] conexão fechada (código ${status}). Reconectando...`);
        setTimeout(() => {
          if (sessoes.get(usuarioId) === s && !s.parar) iniciarSessao(usuarioId);
        }, 3000);
      }
    });
  } catch (err) {
    console.error(`[wa ${usuarioId}] erro ao iniciar:`, err.message);
    s.iniciando = false;
    sessoes.delete(usuarioId);
  }
}

// Encerra a sessão de um cliente. apagar=true também remove as credenciais salvas.
async function pararSessao(usuarioId, { apagar = false, logout = false } = {}) {
  const s = sessoes.get(usuarioId);
  if (s) {
    s.parar = true;
    try {
      if (logout) await s.sock?.logout();
      else s.sock?.end(undefined);
    } catch {
      /* já estava fechada */
    }
    sessoes.delete(usuarioId);
  }
  if (apagar) fs.rmSync(dirSessao(usuarioId), { recursive: true, force: true });
}

// Ao subir o servidor, reconecta quem já tinha o WhatsApp pareado
function retomarSessoesSalvas() {
  const candidatos = db.usuarios.filter((u) => u.ativo && temCredenciais(u.id)).slice(0, MAX_SESSOES);
  candidatos.forEach((u, i) => {
    setTimeout(() => iniciarSessao(u.id), i * 1500); // escalonado para não pesar na subida
  });
  if (candidatos.length) console.log(`Retomando ${candidatos.length} sessão(ões) de WhatsApp...`);
}

// Rotas do WhatsApp (cada cliente enxerga só a própria conexão)
app.get('/api/whatsapp/qrcode', autenticar, (req, res) => {
  const id = req.usuario.id;
  const s = sessoes.get(id);

  if (s?.conectado) {
    return res.json({ conectado: true });
  }

  // ?status=1: só informa o estado, sem abrir conexão nem gerar QR (não gasta recursos)
  if (req.query.status === '1') {
    return res.json({ conectado: false });
  }

  if (!s?.iniciando) {
    if (!s && sessoes.size >= MAX_SESSOES) {
      return res.status(503).json({ erro: 'Limite de conexões simultâneas atingido. Tente novamente mais tarde.' });
    }
    iniciarSessao(id).catch((err) => console.error(`[wa ${id}]`, err.message));
  }

  return res.json({ qrcode: s?.qr || null, conectado: false });
});

app.post('/api/whatsapp/desconectar', autenticar, async (req, res) => {
  await pararSessao(req.usuario.id, { apagar: true, logout: true });
  res.json({ mensagem: 'WhatsApp desconectado.' });
});

// ===================================================================
// Administração (somente administrador)
// ===================================================================
app.get('/api/admin/usuarios', autenticar, somenteAdmin, (req, res) => {
  const lista = db.usuarios.map((u) => ({
    id: u.id,
    nome: u.nome,
    email: u.email,
    role: u.role,
    ativo: u.ativo,
    criadoEm: u.criadoEm,
    ultimoLoginEm: u.ultimoLoginEm || null,
    whatsapp: sessoes.get(u.id)?.conectado ? 'conectado' : 'desconectado',
    agendamentos: db.agendamentos.filter((a) => a.usuarioId === u.id).length,
  }));
  res.json(lista);
});

app.patch('/api/admin/usuarios/:id', autenticar, somenteAdmin, async (req, res) => {
  const alvo = buscarUsuario(Number(req.params.id));
  if (!alvo) return res.status(404).json({ erro: 'Usuário não encontrado.' });
  if (alvo.role === 'admin') return res.status(400).json({ erro: 'Não é possível bloquear um administrador.' });
  if (typeof req.body?.ativo !== 'boolean') return res.status(400).json({ erro: 'Informe "ativo" (true ou false).' });

  alvo.ativo = req.body.ativo;
  salvarDados();

  if (!alvo.ativo) {
    await pararSessao(alvo.id); // desliga o robô, mas mantém o pareamento para quando for liberado
  } else if (temCredenciais(alvo.id)) {
    iniciarSessao(alvo.id).catch((err) => console.error(`[wa ${alvo.id}]`, err.message));
  }

  res.json({ mensagem: alvo.ativo ? 'Conta liberada.' : 'Conta bloqueada.', ativo: alvo.ativo });
});

app.post('/api/admin/usuarios/:id/senha', autenticar, somenteAdmin, async (req, res) => {
  const alvo = buscarUsuario(Number(req.params.id));
  if (!alvo) return res.status(404).json({ erro: 'Usuário não encontrado.' });

  const senha = String(req.body?.senha || '');
  if (senha.length < 6) return res.status(400).json({ erro: 'A senha precisa ter pelo menos 6 caracteres.' });

  alvo.senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
  salvarDados();
  res.json({ mensagem: 'Senha redefinida.' });
});

app.delete('/api/admin/usuarios/:id', autenticar, somenteAdmin, async (req, res) => {
  const alvo = buscarUsuario(Number(req.params.id));
  if (!alvo) return res.status(404).json({ erro: 'Usuário não encontrado.' });
  if (alvo.role === 'admin') return res.status(400).json({ erro: 'Não é possível excluir um administrador.' });

  await pararSessao(alvo.id, { apagar: true, logout: true });

  db.agendamentos = db.agendamentos.filter((a) => a.usuarioId !== alvo.id);
  db.usuarios = db.usuarios.filter((u) => u.id !== alvo.id);
  for (const chave of historicos.keys()) {
    if (chave.startsWith(`${alvo.id}:`)) historicos.delete(chave);
  }
  salvarDados();

  res.json({ mensagem: 'Conta excluída.' });
});

// ===================================================================
// Front-end
// ===================================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, async () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  await garantirAdmin();
  retomarSessoesSalvas();
});
