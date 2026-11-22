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

// ---------- Agendamentos ----------
// Ficam em memória e também são gravados em um arquivo JSON, para sobreviverem a reinícios.
// No Render, aponte DATA_DIR para um disco persistente (ex.: /data); sem isso o arquivo some a cada deploy.
const DATA_DIR = process.env.DATA_DIR || __dirname;
const ARQUIVO_AGENDAMENTOS = path.join(DATA_DIR, 'agendamentos.json');
const FUSO = 'America/Sao_Paulo';

function carregarAgendamentos() {
  try {
    const lista = JSON.parse(fs.readFileSync(ARQUIVO_AGENDAMENTOS, 'utf8'));
    return Array.isArray(lista) ? lista : [];
  } catch {
    return [];
  }
}

function salvarAgendamentos() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(ARQUIVO_AGENDAMENTOS, JSON.stringify(agendamentos, null, 2));
  } catch (err) {
    console.error('Erro ao salvar agendamentos:', err.message);
  }
}

const agendamentos = carregarAgendamentos();
let proximoAgendamentoId = agendamentos.reduce((maior, a) => Math.max(maior, a.id || 0), 0) + 1;

// Data e hora atuais no fuso do Brasil (o servidor do Render roda em UTC)
function agoraNoBrasil() {
  const agora = new Date();
  return {
    data: agora.toLocaleDateString('en-CA', { timeZone: FUSO }), // AAAA-MM-DD
    hora: agora.toLocaleTimeString('pt-BR', { timeZone: FUSO, hour: '2-digit', minute: '2-digit', hour12: false }),
    diaSemana: agora.toLocaleDateString('pt-BR', { timeZone: FUSO, weekday: 'long' }),
  };
}

const dataParaBR = (iso) => iso.split('-').reverse().join('/');

function criarAgendamento(jid, dados) {
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

  if (agendamentos.some((a) => a.data === data && a.horario === horario)) {
    return { ok: false, motivo: 'ocupado' };
  }

  const agendamento = {
    id: proximoAgendamentoId++,
    cliente,
    servico,
    data,
    horario,
    contato: jid && jid.endsWith('@s.whatsapp.net') ? jid.split('@')[0] : null,
    jid: jid || null, // uso interno: o bot usa para lembrar dos agendamentos de cada cliente
    criadoEm: new Date().toISOString(),
  };
  agendamentos.push(agendamento);
  salvarAgendamentos();
  return { ok: true, agendamento };
}

app.get('/api/agendamentos', autenticar, (req, res) => {
  const lista = [...agendamentos]
    .sort((a, b) => `${a.data} ${a.horario}`.localeCompare(`${b.data} ${b.horario}`))
    .map(({ jid, ...publico }) => publico); // o jid não vai para o painel
  res.json(lista);
});

// ---------- Robô de atendimento (IA / Groq) ----------
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

// Prompt GLOBAL: serve para qualquer empresa. Os dados do negócio vêm das variáveis de ambiente
// EMPRESA_NOME e EMPRESA_INFO. Se quiser trocar a personalidade inteira, defina BOT_SYSTEM_PROMPT.
const PROMPT_BASE =
  process.env.BOT_SYSTEM_PROMPT ||
  `Você é o atendente virtual da empresa, atendendo clientes pelo WhatsApp.
- Seja educado, simpático e objetivo. Escreva em português do Brasil, com mensagens curtas (no máximo 3 frases).
- Ajude o cliente a tirar dúvidas sobre a empresa e a marcar horário.
- Use SOMENTE as informações da empresa fornecidas abaixo. Se não souber algo (preço, endereço, prazo, disponibilidade), diga que vai confirmar com a equipe. Nunca invente.
- Não converse sobre assuntos que não tenham relação com o atendimento da empresa.`;

const EMPRESA_NOME = process.env.EMPRESA_NOME || '';
const EMPRESA_INFO = process.env.EMPRESA_INFO || '';

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

// Monta o prompt completo de cada conversa, com a data de hoje e os agendamentos
function construirSystemPrompt(jid) {
  const agora = agoraNoBrasil();
  const partes = [PROMPT_BASE];

  if (EMPRESA_NOME) partes.push(`Nome da empresa: ${EMPRESA_NOME}`);
  if (EMPRESA_INFO) partes.push(`Informações da empresa (serviços, preços, horário de funcionamento, endereço):\n${EMPRESA_INFO}`);

  partes.push(PROTOCOLO_AGENDAMENTO);
  partes.push(`Hoje é ${agora.diaSemana}, ${dataParaBR(agora.data)} (${agora.data}). Agora são ${agora.hora} (horário de Brasília).`);

  const futuros = agendamentos.filter((a) => a.data >= agora.data);

  const doCliente = futuros.filter((a) => a.jid === jid);
  partes.push(
    doCliente.length
      ? `Agendamentos deste cliente:\n${doCliente
          .map((a) => `- ${dataParaBR(a.data)} às ${a.horario}: ${a.servico} (em nome de ${a.cliente})`)
          .join('\n')}`
      : 'Agendamentos deste cliente: nenhum.'
  );

  // Só data e horário: não revelamos o nome de outros clientes
  const ocupados = futuros.slice(0, 80).map((a) => `${dataParaBR(a.data)} às ${a.horario}`);
  partes.push(`Horários já ocupados (não oferecer): ${ocupados.length ? ocupados.join('; ') : 'nenhum.'}`);

  return partes.join('\n\n');
}

// Procura o comando de agendamento na resposta da IA, registra no painel e limpa o texto
const REGEX_AGENDAR = /\[\[\s*AGENDAR\s*(\{[\s\S]*?\})\s*\]\]/;
const REGEX_AGENDAR_QUALQUER = /\[\[\s*AGENDAR[\s\S]*?\]\]/g;

function processarAgendamentoDaResposta(jid, resposta) {
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

  const resultado = criarAgendamento(jid, dados);

  if (resultado.ok) {
    const a = resultado.agendamento;
    console.log(`[bot] agendamento #${a.id} criado: ${a.cliente}, ${a.servico}, ${a.data} ${a.horario}`);
    return texto || `Agendamento confirmado: ${a.servico} em ${dataParaBR(a.data)} às ${a.horario}, no nome de ${a.cliente}.`;
  }

  console.log(`[bot] agendamento recusado (${resultado.motivo}).`);
  if (resultado.motivo === 'ocupado') {
    return 'Poxa, esse horário acabou de ser ocupado. Pode escolher outro horário?';
  }
  if (resultado.motivo === 'passado') {
    return 'Esse horário já passou. Pode me passar uma data e um horário futuros?';
  }
  return 'Não consegui registrar o agendamento. Pode me confirmar nome, serviço, data e horário?';
}

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
      messages: [{ role: 'system', content: construirSystemPrompt(jid) }, ...historico],
      temperature: 0.5,
      max_tokens: 400,
    });

    const respostaBruta = completion.choices?.[0]?.message?.content?.trim() || '';
    const resposta = respostaBruta ? processarAgendamentoDaResposta(jid, respostaBruta) : '';
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