import axios from 'axios';
import cfonts from 'cfonts';
import chalk from 'chalk';
import ora from 'ora';
import readline from 'readline';
import { Wallet } from 'ethers';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import fs from 'fs/promises';
import { faker } from '@faker-js/faker';

function delay(seconds) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

async function countdownDelay(seconds) {
  let remaining = seconds;
  process.stdout.write(chalk.yellow(`Waiting ${remaining} seconds before next account...`));
  const interval = setInterval(() => {
    remaining--;
    process.stdout.write(`\r${chalk.yellow(`Waiting ${remaining} seconds before next account...`)}`);
    if (remaining <= 0) {
      clearInterval(interval);
      process.stdout.write('\r' + ' '.repeat(process.stdout.columns) + '\r');
    }
  }, 1000);
  await delay(seconds);
}

function centerText(text, color = 'greenBright') {
  const terminalWidth = process.stdout.columns || 80;
  const textLength = text.length;
  const padding = Math.max(0, Math.floor((terminalWidth - textLength) / 2));
  return ' '.repeat(padding) + chalk[color](text);
}

const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
];

function getRandomUserAgent() {
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function getHeaders(token = null) {
  const headers = {
    'User-Agent': getRandomUserAgent(),
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'Referer': 'https://app.stobix.com/'
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function getAxiosConfig(proxy, token = null) {
  const config = {
    headers: getHeaders(token),
    timeout: 60000
  };
  if (proxy) {
    config.httpsAgent = newAgent(proxy);
  }
  return config;
}

function newAgent(proxy) {
  if (proxy.startsWith('http://') || proxy.startsWith('https://')) {
    return new HttpsProxyAgent(proxy);
  } else if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
    return new SocksProxyAgent(proxy);
  } else {
    console.log(chalk.red(`Unsupported proxy type: ${proxy}`));
    return null;
  }
}

async function requestWithRetry(method, url, payload = null, config = null, retries = 3, backoff = 2000) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try {
      let response;
      if (method === 'get') {
        response = await axios.get(url, config);
      } else if (method === 'post') {
        response = await axios.post(url, payload, config);
      } else if (method === 'put') {
        response = await axios.put(url, payload, config);
      } else {
        throw new Error(`Unsupported method: ${method}`);
      }
      return response;
    } catch (error) {
      lastError = error;
      let errorMessage = error.message;
      let statusCode = error.response ? error.response.status : null;
      if (error.response) {
        const rawData = error.response.data;
        if (typeof rawData === 'string' || Buffer.isBuffer(rawData)) {
          errorMessage = `Invalid response: ${rawData.toString().substring(0, 200)}`;
        } else {
          errorMessage = error.response.data?.message || error.response.data?.error || error.message;
        }
      }

      if (i < retries - 1 && (statusCode === 429 || statusCode === 501)) {
        console.log(chalk.yellow(`Retry ${i + 1}/${retries} for ${url}: ${errorMessage}`));
        await delay(backoff / 1000);
        backoff *= 1.5;
        continue;
      }
    }
  }
  throw lastError;
}

async function readPrivateKeys() {
  try {
    const data = await fs.readFile('pk.txt', 'utf-8');
    return data
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .map(pk => pk.startsWith('0x') ? pk : `0x${pk}`);
  } catch (error) {
    console.error(chalk.red(`Error reading pk.txt: ${error.message}`));
    return [];
  }
}

async function readProxies() {
  try {
    const data = await fs.readFile('proxy.txt', 'utf-8');
    return data
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0);
  } catch (error) {
    console.error(chalk.red(`Error reading proxy.txt: ${error.message}`));
    return [];
  }
}

async function getPublicIP(proxy) {
  try {
    const response = await requestWithRetry('get', 'https://api.ipify.org?format=json', null, getAxiosConfig(proxy));
    return response.data?.ip || 'IP tidak ditemukan';
  } catch (error) {
    return 'Error mengambil IP';
  }
}

async function authenticateWallet(walletAddress, privateKey, proxy) {
  const wallet = new Wallet(privateKey);
  const spinnerAuth = ora({ text: ' Process Login...', spinner: 'dots2', color: 'cyan' }).start();

  try {
    const nonceUrl = 'https://api.stobix.com/v1/auth/nonce';
    const noncePayload = { address: walletAddress };
    const nonceConfig = getAxiosConfig(proxy);
    const nonceResponse = await requestWithRetry('post', nonceUrl, noncePayload, nonceConfig);
    const { nonce } = nonceResponse.data;

    let n_sig = '';
    const setCookie = nonceResponse.headers['set-cookie'];
    if (setCookie && setCookie.length > 0) {
      const nSigMatch = setCookie[0].match(/n_sig=([^;]+)/);
      if (nSigMatch) {
        n_sig = nSigMatch[1];
      }
    }

    spinnerAuth.text = ' Process Sign Wallet...';
    await delay(0.5);

    const message = `Sign this message to authenticate: ${nonce}`;
    const signature = await wallet.signMessage(message);
    spinnerAuth.text = ' Sign Success...';
    await delay(0.5);

    const verifyUrl = 'https://api.stobix.com/v1/auth/web3/verify';
    const verifyPayload = { nonce, signature };
    const verifyConfig = getAxiosConfig(proxy);
    if (n_sig) {
      verifyConfig.headers.Cookie = `n_sig=${n_sig}`;
    }
    const verifyResponse = await requestWithRetry('post', verifyUrl, verifyPayload, verifyConfig);
    const { token } = verifyResponse.data;

    spinnerAuth.succeed(chalk.greenBright(' Login Successfully'));
    return token;
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinnerAuth.fail(chalk.redBright(` Login Failed: ${errorMessage}`));
    throw error;
  }
}

function getDateString(date) {
  return date.toISOString().slice(0, 10);
}

async function completeTasks(walletAddress, proxy, token) {
  const loyaltyUrl = 'https://api.stobix.com/v1/loyalty';
  const spinnerTasks = ora({ text: ' Fetching Task List...', spinner: 'dots2', color: 'cyan' }).start();

  try {
    const loyaltyResponse = await requestWithRetry('get', loyaltyUrl, null, getAxiosConfig(proxy, token));
    const tasks = loyaltyResponse.data.tasks;

    spinnerTasks.succeed(chalk.greenBright(' Task List Received'));

    const today = getDateString(new Date());

    for (let i = 0; i < tasks.length; i++) {
      const task = tasks[i];
      const { id, claimedAt, frequency } = task;

      if (id !== 'retweet_x') {
        continue;
      }

      if (frequency !== 'daily') {
        continue;
      }

      let canClaim = true;
      if (claimedAt !== null) {
        const claimedDate = getDateString(new Date(claimedAt));
        if (claimedDate === today) {
          canClaim = false;
          console.log(chalk.bold.greenBright(`  🎯 Task ${id} Already Done Today`));
        }
      }

      if (!canClaim) {
        continue;
      }

      const spinnerClaim = ora({ text: `  Completing Task ${id}...`, spinner: 'dots2', color: 'cyan' }).start();
      try {
        const claimUrl = 'https://api.stobix.com/v1/loyalty/tasks/claim';
        const claimPayload = { taskId: id };
        const claimResponse = await requestWithRetry('post', claimUrl, claimPayload, getAxiosConfig(proxy, token));
        const { points } = claimResponse.data;
        spinnerClaim.succeed(chalk.greenBright(` Completing Task ${id} Successfully`));
      } catch (error) {
        const errorMessage = error.message || 'Unknown error';
        spinnerClaim.fail(chalk.redBright(` Failed Completing Task ${id}: ${errorMessage}`));
      }
    }
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinnerTasks.fail(chalk.redBright(` Failed Receiving Task List: ${errorMessage}`));
  }
}

async function getMiningStatus(proxy, token) {
  const loyaltyUrl = 'https://api.stobix.com/v1/loyalty';
  const loyaltyResponse = await requestWithRetry('get', loyaltyUrl, null, getAxiosConfig(proxy, token));
  return loyaltyResponse.data.user;
}

async function connectTwitter(proxy, token, spinner) {
  spinner.text = '🔗 Connecting Twitter Account...';
  const twitterUsername = faker.internet.username().toLowerCase();
  const twitterUrl = `https://x.com/${twitterUsername}`;
  const updatePayload = { twitter: twitterUrl };

  try {
    const updateUrl = 'https://api.stobix.com/v1/loyalty/me';
    const updateResponse = await requestWithRetry('put', updateUrl, updatePayload, getAxiosConfig(proxy, token));
    spinner.succeed(chalk.greenBright(` Twitter Connected: ${twitterUrl}`));
    console.log(chalk.greenBright(`  Twitter Connected: ${twitterUrl}`));
    return true;
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinner.fail(chalk.redBright(` Failed to Connect Twitter: ${errorMessage}`));
    return false;
  }
}

async function claimMiningPoints(proxy, token) {
  const spinnerClaim = ora({ text: ' Claiming Mining Points...', spinner: 'dots2', color: 'cyan' }).start();
  const claimUrl = 'https://api.stobix.com/v1/loyalty/points/claim';
  try {
    const claimResponse = await requestWithRetry('post', claimUrl, {}, getAxiosConfig(proxy, token));
    const { points } = claimResponse.data;
    spinnerClaim.succeed(chalk.greenBright(` Mining Points Claimed: ${points}`));
    return { success: true, points };
  } catch (error) {
    if (error.response && error.response.data && error.response.data.code === 'X_REQUIRED') {
      const connected = await connectTwitter(proxy, token, spinnerClaim);
      if (connected) {
        return await claimMiningPoints(proxy, token);
      } else {
        spinnerClaim.fail(chalk.redBright(` Failed to Claim Mining Points after Twitter Connect`));
        return { success: false };
      }
    } else {
      const errorMessage = error.message || 'Unknown error';
      spinnerClaim.fail(chalk.redBright(` Failed to Claim Mining Points: ${errorMessage}`));
      return { success: false };
    }
  }
}

async function startMining(proxy, token) {
  const spinnerMine = ora({ text: '⛏️  Starting Mining...', spinner: 'dots2', color: 'cyan' }).start();
  try {
    const mineUrl = 'https://api.stobix.com/v1/loyalty/points/mine';
    const mineResponse = await requestWithRetry('post', mineUrl, {}, getAxiosConfig(proxy, token));
    const { amount, startedAt, claimAt } = mineResponse.data;
    spinnerMine.succeed(chalk.greenBright(` Mining Started Successfully: ${amount} Points, Claim at ${claimAt}`));
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinnerMine.fail(chalk.redBright(` Failed to Start Mining: ${errorMessage}`));
  }
}

async function handleMining(proxy, token) {
  const spinnerCheck = ora({ text: ' Checking Mining Status...', spinner: 'dots2', color: 'cyan' }).start();

  let miningStartedAt, miningClaimAt;
  try {
    const user = await getMiningStatus(proxy, token);
    ({ miningStartedAt, miningClaimAt } = user);
    spinnerCheck.succeed(chalk.greenBright(' Mining Status Checked'));
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinnerCheck.fail(chalk.redBright(` Error Checking Mining Status: ${errorMessage}`));
    return;
  }

  const now = new Date();
  const claimTime = miningClaimAt ? new Date(miningClaimAt) : null;

  if (claimTime && claimTime <= now) {
    const claimResult = await claimMiningPoints(proxy, token);
    if (!claimResult.success) {
      return;
    }
    const updatedUser = await getMiningStatus(proxy, token);
    ({ miningStartedAt, miningClaimAt } = updatedUser);
  } else if (miningStartedAt && claimTime && claimTime > now) {
    console.log(chalk.greenBright(` Mining Already Started, Next Claim at ${miningClaimAt}`));
    return;
  }

  await startMining(proxy, token);
}

async function getUserPoints(proxy, token) {
  const loyaltyUrl = 'https://api.stobix.com/v1/loyalty';
  const spinnerPoints = ora({ text: ' Getting Points...', spinner: 'dots2', color: 'cyan' }).start();

  try {
    const loyaltyResponse = await requestWithRetry('get', loyaltyUrl, null, getAxiosConfig(proxy, token));
    const points = loyaltyResponse.data.user.points;
    spinnerPoints.succeed(chalk.greenBright(` Total Points: ${points}`));
    return points;
  } catch (error) {
    const errorMessage = error.message || 'Unknown error';
    spinnerPoints.fail(chalk.redBright(` Error Getting Points: ${errorMessage}`));
    return null;
  }
}

async function processAccount(privateKey, index, total, proxy) {
  const wallet = new Wallet(privateKey);
  const walletAddress = wallet.address;

  console.log(`\n`);
  console.log(chalk.bold.cyanBright('='.repeat(80)));
  console.log(chalk.bold.whiteBright(`Akun: ${index + 1}/${total}`));
  console.log(chalk.bold.whiteBright(`Wallet: ${walletAddress}`));
  const usedIP = await getPublicIP(proxy);
  console.log(chalk.bold.whiteBright(`Using IP: ${usedIP}`));
  console.log(chalk.bold.cyanBright('='.repeat(80)));

  try {
    if (wallet.address.toLowerCase() !== walletAddress.toLowerCase()) {
      throw new Error('Private key does not match wallet address');
    }
  } catch (error) {
    console.error(chalk.red(`Invalid wallet: ${error.message}`));
    return;
  }

  let token;
  try {
    token = await authenticateWallet(walletAddress, privateKey, proxy);
  } catch (error) {
    console.error(chalk.red(`Error autentikasi: ${error.message}`));
    return;
  }

  await completeTasks(walletAddress, proxy, token);

  await handleMining(proxy, token);

  await getUserPoints(proxy, token);
}

async function main() {
  cfonts.say('NT EXHAUST', {
    font: 'block',
    align: 'center',
    colors: ['cyan', 'magenta'],
    background: 'transparent',
    letterSpacing: 1,
    lineHeight: 1,
    space: true,
    maxLength: '0'
  });
  console.log(centerText("=== Telegram Channel 🚀 : NT Exhaust (@NTExhaust) ===\n"));
  console.log(centerText("✪ STOBIX AUTO RUN NODE ✪ \n"));

  const useProxyAns = await askQuestion('Ingin menggunakan proxy? (y/n): ');
  let proxies = [];
  let useProxy = false;
  if (useProxyAns.trim().toLowerCase() === 'y') {
    useProxy = true;
    proxies = await readProxies();
    if (proxies.length === 0) {
      console.log(chalk.yellow('Tidak ada proxy di proxy.txt. Lanjut tanpa proxy.'));
      useProxy = false;
    }
  }

  const privateKeys = await readPrivateKeys();
  if (privateKeys.length === 0) {
    console.log(chalk.red('Tidak ada private key di pk.txt.'));
    return;
  }

  async function runCycle() {
    for (let i = 0; i < privateKeys.length; i++) {
      const proxy = useProxy ? proxies[i % proxies.length] : null;
      try {
        await processAccount(privateKeys[i], i, privateKeys.length, proxy);
      } catch (error) {
        console.error(chalk.red(`Error pada akun ${i + 1}: ${error.message}`));
      }
      if (i < privateKeys.length - 1) {
        const randomSeconds = Math.floor(Math.random() * 5) + 10;
        await countdownDelay(randomSeconds);
      }
    }
    console.log(chalk.magentaBright('All Accounts Processed, Waiting 8 Hours Before Next Cycle'));
    await delay(28800);
    runCycle();
  }

  runCycle();
}

function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

main();