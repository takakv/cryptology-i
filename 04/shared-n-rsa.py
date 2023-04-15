import  random, math, time
from Crypto.Util.number import getPrime

#"Crypto" might need "pip install pycryptodome" if it's not installed

#given integers a, b, returns integers g, x,y such that g is the gcd of a and b and g=x*a+y*b
#from https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

#returns the modular inverse of a modulo m. 
#from https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m           

# Generate the values N, phi(N), p, q
def generateGeneralKeys(bits):
    p=getPrime(bits)
    q=getPrime(bits)
    N=p*q
    phiN=(p-1)*(q-1)
    return (N,phiN,p,q)


#this will output a pair (d,e) such that e is coprime with phiN and d*e=1 mod phi(N)
def generatePartyKeys(N,phiN,bits):
    noKeyYet=True
    while(noKeyYet):
        e= random.randint(0,2**(2*bits))
        if(math.gcd(e,phiN)==1):
            d=modinv(e,phiN)
            noKeyYet=False
    return (e,d)
    
#this function gets phi(N)=(p-1)*(q-1) and N=p*q as inputs and outputs p and q    
def fromPhiNToFactors(phiN,N):
    pPlusQ=N-phiN+1 #from p*q and (p-1)*(q-1) easy to compute p+q
    p= (pPlusQ + math.sqrt(pPlusQ**2-4*N))/2 #from p+q and p*q easy to compute p and q
    q= (pPlusQ - math.sqrt(pPlusQ**2-4*N))/2
    return (p,q)

#this tests whether you have found the correct factors.
def testSolution(N,p,q):
    if(p==1 or q==1):
        return 0
    if(int(p)*int(q)==N):
        return 1
    else:
        return 0

#it is your job to define this adversary
def adv1(bits, N, e1, d1, e2,d2):
    k1 = (e1 * d1) - 1
    k2 = (e2 * d2) - 1
    phi_candidate = math.gcd(k1, k2)
    b_val = N + 1 - phi_candidate
    delta = pow(b_val, 2) - (4 * N)
    q = (b_val + math.isqrt(delta)) // 2
    p = N // q
    return (p,q)
    
#this is the game    
def oneGame(bits, adv):
    (N,phiN,p,q)=generateGeneralKeys(bits)
    (e1,d1)=generatePartyKeys(N,phiN,bits)
    (e2,d2)=generatePartyKeys(N,phiN,bits)    
    (p,q)=adv(bits, N, e1, d1, e2,d2)
    isSuccessful=testSolution(N,p,q)
    return isSuccessful
    
#use this to test your solution    
def testSharedNRSA(bits,times,adv):
    start_time = time.time()
    count=0
    for i in range(times):
        count+=oneGame(bits,adv)
    ratio= (1.0*count)/times
    print("ratio=", ratio)
    print("number of successes=", count)
    print("--- %s seconds ---" % (time.time() - start_time))


testSharedNRSA(50,100, adv1)    
    
    
    
    
