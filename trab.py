import time
import random

def strToBits(s):
  bits = []
  for char in s:
    binVal = bin(ord(char))[2:].zfill(8) # ord retorna valor acii e bin converte para binario
    bits.extend([int(b) for b in binVal]) # zfill eh so pra garantir que tem 8 bits
  return bits

def bitsToInt(bits):
  val = 0
  for b in bits:
    val = (val << 1) | b # shift left e addicao do bit
  return val

def bitsToStr(bits):
  chars = []
  for i in range(0, len(bits), 8): # pega de 8 em 8 bits, pq 1 byte = 8 bits
    byte = bits[i:i+8]

    if len(byte) < 8: # se menor que 8, quer dizer que eh lixo, ignora
      break 
    chars.append(chr(bitsToInt(byte)))
  return ''.join(chars)

def xor(a, b):
  return [x ^ y for x, y in zip(a, b)]

def bitsToIntb(bits):
    value = 0
    for b in bits:
        value = (value << 1) | b
    return value
def randomPass(bits, rng):
    return [rng.getrandbits(1) for _ in range(len(bits))]
def xorPass(bits, rng):
    return [b ^ rng.getrandbits(1) for b in bits]

def GEN(seed):
  seedBits = []
  if isinstance(seed, str):
    seedBits = strToBits(seed)
  elif isinstance(seed, list):
    seedBits = seed
  else:
    seedBits = strToBits(str(seed))


  seedInt = bitsToIntb(seedBits)
  rng = random.Random(seedInt)
  K = []
  curr = seedBits.copy()

  for i in range(4):
    curr = xorPass(curr, rng)
    
    curr = fFunction(curr, seedBits)
    rngi = random.Random(seedInt + i)
    curr = randomPass(curr, rngi)
    K.extend(curr)

  return K



# Função F do Feistel
def fFunction(R, k):
  if not R: return []
  
  # rVal: representacao do lado direito R em inteiro
  # kVal: representacao da subchave k em inteiro
  rVal = bitsToInt(R)
  kVal = bitsToInt(k)

  # equivalente a 2^{len(R)} - 1
  mask = (1 << len(R)) - 1
  
  # xor entre R e k
  temp = rVal ^ kVal
  
  # temp = (temp * 27 + 55) mod 2^{len(R)}
  temp = (temp * 0x1B + 0x37) & mask 
  
  # temp = (temp << 3) | (temp >> (len(R) - 3))
  shift = 3
  temp = ((temp << shift) & mask) | (temp >> (len(R) - shift))
  
  resBin = bin(temp)[2:].zfill(len(R))
  return [int(b) for b in resBin]

def ENC(K, M):
  if len(K) != len(M):
    pass

  n = len(M)
  half = int(n / 2)
  
  L = M[:half]
  R = M[half:]
  
  originalKL = K[:half]
  originalKR = K[half:]
  
  rounds = 50
  
  for i in range(rounds):
    LPrev = L
    RPrev = R
    
    if i % 2 == 0:
      currentK = originalKL
    else:
      currentK = originalKR
      
    rot = (i * 3) % len(currentK)
    if len(currentK) > 0:
      currentK = currentK[rot:] + currentK[:rot]
      
    # Rede de Feistel:
    # Li+1 = Ri
    # Ri+1 = Li xor F(Ri, Ki)
    L = RPrev
    funcOut = fFunction(RPrev, currentK)
    R = xor(LPrev, funcOut)
    
  return L + R

def DEC(K, C):
  n = len(C)
  half = int(n / 2)
  
  L = C[:half]
  R = C[half:]
  
  originalKL = K[:half]
  originalKR = K[half:]
  
  rounds = 50
  
  subkeys = []
  for i in range(rounds):
    if i % 2 == 0:
      currentK = originalKL
    else:
      currentK = originalKR
      
    rot = (i * 3) % len(currentK)
    if len(currentK) > 0:
      currentK = currentK[rot:] + currentK[:rot]
    subkeys.append(currentK)
    
  # na dec as chaves sao usadas na ordem inversa
  subkeysRev = subkeys.copy()
  subkeysRev.reverse()
  
  for i in range(rounds):
    currentL = L
    currentR = R
    
    # Feistel Inverso:
    # Ri = Li+1
    # Li = Ri+1 xor F(Li+1, Ki)
    
    recoveredR = currentL
    recoveredL = xor(currentR, fFunction(recoveredR, subkeysRev[i]))
    
    L = recoveredL
    R = recoveredR
    
  return L + R

# Calcula o tempo medio de execucao de 100 operacoes de criptografia
def evalTime(seedVal, msgStr):
  K = GEN(seedVal)
  M = strToBits(msgStr)
  
  start = time.perf_counter()
  for _ in range(100):
    ENC(K, M)
  end = time.perf_counter()
  
  avgTime = (end - start) / 100
  return avgTime

# Verifica se chaves diferentes produzem cifras iguais
def testEquivalentKeys(msgStr):
  M = strToBits(msgStr)
  
  totalBits = len(M)
  seedBitsLen = int(totalBits / 4)
  seedChars = int(seedBitsLen / 8)
  
  if seedChars < 1: 
    seedChars = 1
  
  baseSeeds = ["A"*seedChars, "B"*seedChars, "C"*seedChars, 
               "a"*seedChars, "b"*seedChars]
               
  seeds = [] # gerando variações das seeds base
  for i, s in enumerate(baseSeeds):
    prefix = s[:-1]
    last = chr(ord(s[-1]) + i) # ord pra pegar ascii e somar i pra variar
    seeds.append(prefix + last)

  cipherMap = {}
  collisions = 0
  
  for s in seeds:
    K = GEN(s)
    
    if len(K) != len(M):
      continue
      
    CTuple = tuple(ENC(K, M)) 
    
    if CTuple in cipherMap:
      prevSeed = cipherMap[CTuple]
      KPrev = GEN(prevSeed)
      if K != KPrev:
        collisions += 1
    else:
      cipherMap[CTuple] = s
      
  return collisions

# Avalia a difusao: quantos bits da cifra mudam ao alterar 1 bit da mensagem
def testDiffusion(seedVal, msgStr):
  K = GEN(seedVal)
  M = strToBits(msgStr)
  C1 = ENC(K, M)
  
  MMod = list(M)
  idx = 0 
  MMod[idx] = 1 - MMod[idx]
  
  C2 = ENC(K, MMod)
  
  diffBits = sum(xor(C1, C2))
  return diffBits, len(C1)

# Avalia a confusao: quantos bits da cifra mudam ao alterar 1 bit da seed
def testConfusion(seedVal, msgStr):
  M = strToBits(msgStr)
  
  seedBits = strToBits(seedVal)
  
  K1 = []
  for _ in range(4): 
    K1.extend(seedBits)
  C1 = ENC(K1, M)
  
  seedBitsMod = list(seedBits)
  seedBitsMod[0] = 1 - seedBitsMod[0]
  
  K2 = []
  for _ in range(4): 
    K2.extend(seedBitsMod)
  
  C2 = ENC(K2, M)
  
  diffBits = sum(xor(C1, C2))
  return diffBits, len(C1)

if __name__ == "__main__":
  seedInput = "ALIRIO-SEG-1234567890"
  msgInput = "UFUSEG210-SEGSEGSEGSEGSEG-SEGSEGSEGSEGSEG"
  
  print(f"Configs")
  print(f"Seed: {seedInput}")
  print(f"Mensagem : {msgInput}")
  
  K = GEN(seedInput)
  print(f"Tamanho da Chave: {len(K)} bits")
  
  M = strToBits(msgInput)
  C = ENC(K, M)
  print(f"Cifra em hexa: {hex(bitsToInt(C))}")
  
  MDec = DEC(K, C)
  print(f"Mensagem Descriptografada: {bitsToStr(MDec)}")
  
  if M != MDec:
    print("ERRO na DEC")
  
  print("Testes:")
  
  t = evalTime(seedInput, msgInput)
  print(f"Tempo Médio: {t:.8f} s")
  
  cols = testEquivalentKeys(msgInput)
  print(f"Chaves Equivalentes detectadas: {cols}")
  
  dif, tot = testDiffusion(seedInput, msgInput)
  print(f"Difusão (Muda 1 bit da Msg): {dif} bits alterados de {tot} ({dif/tot:.2%})")
  
  conf, tot = testConfusion(seedInput, msgInput)
  print(f"Confusão (Muda 1 bit Seed): {conf} bits alterados de {tot} ({conf/tot:.2%})")