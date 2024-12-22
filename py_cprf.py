import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import itertools
from itertools import combinations

class cPRF:
    def __init__(self, t, l, lambda_=128):
        """
        初始化AES_cPRF类。
        :param t: 子集的大小 (CNF locality)
        :param l: 输入长度的上限
        """
        self.t = t
        self.log_t = t.bit_length()
        self.l = l
        self.lambda_ = lambda_
        self.seed = 'cprF'
        self.msk = None
        self.pp = None

    def encode_vt(self, a):
        print(a)
        return "".join([bin(i)[2:].zfill(self.log_t) for i in a[0]]) + a[1]

    def aes_prf(self, input_bits, key):
        # AES计算逻辑
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(input_bits)
        return encrypted
    
    def lambda_bit_prf(self, input_bits, key_as_seed):
        
        if len(input_bits) > self.lambda_ or any(bit not in '01' for bit in input_bits):
            raise ValueError(f'input_bits 必须是小于{self.lambda_}位的比特字符串, 现有字符串位数为{len(input_bits)}')
        elif len(input_bits) < self.lambda_:
            input_bits = input_bits.zfill(self.lambda_)
        random.seed(key_as_seed)
        keys = [''.join(bits) for bits in itertools.product('01', repeat=self.lambda_)]
        values = keys.copy()
        random.shuffle(values)
        prf_table = dict(zip(keys, values))
        return prf_table.get(input_bits, '0' * self.lambda_)


    def Setup(self):
        """
        生成公共参数 (pp) 和主密钥 (msk)。
        """
        # self.msk = os.urandom(16)  # 生成128位AES密钥
        self.msk = hashlib.sha256(self.seed.encode()).digest()
        self.pp = (self.t, self.l)            # 公共参数 (此示例中未使用)
        return self.pp, self.msk
    
    def _get_subsets(self, x):
        """
        获取所有长度为t的索引子集及其对应的位串。
        :param x: 输入字符串
        :return: 所有满足长度为t的(T, v)对
        """
        indices = list(range(len(x)))
        subsets = []
        for T in combinations(indices, self.t):
            v = ''.join(x[i] for i in T)
            subsets.append((T, v))
        return subsets
    

    def Eval(self, x):
        """
        使用主密钥 (msk) 评估PRF。
        :param x: 输入字符串
        :return: PRF的输出
        """
        if self.lambda_ == 128:
            S_x = self._get_subsets(x)
            # print('S_x', S_x)
            result = 0      
            for T, v in S_x:
                # 生成子密钥 sk_T_v
                # sk_T_v = self.aes_prf(pad(str(T).encode() + v.encode(), 16), self.msk)
                sk_T_v = self.aes_prf(pad(str(T).encode() + v.encode(), 16), self.msk)
                # print(f'orgianl: ({T,v}):{sk_T_v}')
                # 使用子密钥评估AES并异或结果
                result ^= int.from_bytes(self.aes_prf(pad(x.encode(), 16), sk_T_v), 'big')
            return result
        else:
            if len(x) > self.lambda_ or any(bit not in '01' for bit in x):
                raise ValueError(f'input_bits 必须是小于{self.lambda_}位的比特字符串')
            S_x = self._get_subsets(x)
            # print('S_x', S_x)
            result = 0      
            for T, v in S_x:
                # 生成子密钥 sk_T_v
                sk_T_v = self.lambda_bit_prf(self.encode_vt((T, v)), self.msk)
                # print(f'orgianl: ({T,v}):{sk_T_v}')
                # 使用子密钥评估AES并异或结果
                result ^= int(self.lambda_bit_prf(x, sk_T_v), 2)
            return result

            
            prf_result = self.Two_bit_prf(input_bits, self.seed)
        
    
    def Constrain(self, f):
        """
        生成受限密钥。
        :param f: CNF子句集合，每个子句为(Ti, fi)
        :return: 受限密钥 sk_f
        """
        Sf_i = []
        all_subsets = []

        for s in [''.join(bits) for bits in itertools.product('01', repeat=self.l)]:
            all_subsets.extend(self._get_subsets(s))  # 假设输入长度为l
        # print('all_subsets', all_subsets)
        
        # 解析f中的子句
        for Ti, fi in f:
            Sf_i.extend([(T, v) for T, v in all_subsets if T == Ti and fi(v) == 1])
        
        Sf_rest = [(T, v) for T, v in all_subsets if all(Ti != T for Ti, _ in f)]
        Sf = Sf_rest + Sf_i
        Sf = sorted(list(set(Sf)), key=lambda item: item[0])
        # Sf = sorted(list((Sf)), key=lambda item: item[0])
        # print('Sf:', [Sf[i:i+5] for i in range(0, len(Sf), 5)])
        # 打印Sf中的元素，每行五个
        # for i in range(0, len(Sf), 5):
        #     print(Sf[i:i+5])

        # 生成受限密钥

        
        sk_f = {}
        for T, v in Sf:
            if self.lambda_ == 128:
                
                sk_f[(T, v)] = self.aes_prf(pad(str(T).encode() + v.encode(), 16), self.msk)
                # print(f'constran_eval:({T,v}):{sk_f[(T, v)]}')
                # sk_f[(T, v)] = self.aes_prf(pad(str(T).encode() + v.encode(), 16), self.msk)
                # print(f'constran_eval:({T,v}):{sk_f[(T, v)]}')
            else:
                
                # print(f'({T,v}):{self.encode_vt((T, v))}')
                sk_f[(T, v)] = self.lambda_bit_prf(self.encode_vt((T, v)) , self.msk)
        
        return sk_f
    
    def Eval_sk(self, sk_f, x):
        """
        使用受限密钥评估PRF。
        :param sk_f: 受限密钥
        :param x: 输入字符串
        :return: PRF的输出
        """
        S_x = self._get_subsets(x)
        # print(S_x)
        result = 0
        
        for T, v in S_x:
            if (T, v) in sk_f:
                sk_T_v = sk_f[(T, v)]
                # print(f'({T,v}):{sk_T_v}')
                if self.lambda_ == 128:
                    result ^= int.from_bytes(self.aes_prf(pad(x.encode(), 16), sk_T_v), 'big')
                else:
                    if len(x) > self.lambda_ or any(bit not in '01' for bit in x):
                        raise ValueError(f'input_bits 必须是小于{self.lambda_}位的比特字符串')
                    result ^= int(self.lambda_bit_prf(x, sk_T_v), 2)
                # result ^= int.from_bytes(self.aes_prf(pad(x.encode(), 16), sk_T_v), 'big')
        
        return result

# 使用示例
# ...existing code...
# 使用示例
if __name__ == "__main__":

    t = 1  # 子集的大小
    l = 2  # 输入长度
    lambda_ = 4  # AES密钥长度
    
    # lambda_ = t * (l-1).bit_length() + t  # AES密钥长度
    cprf = cPRF(t, l, lambda_=lambda_)
    
    # 设置阶段
    pp, msk = cprf.Setup()
    # print("Master Secret Key (msk):", msk.hex())
    
    # 定义策略 f
    # f = [
    #     ((0, 1), lambda v: v == "10"),  # 子句1：索引子集为(0, 1)，位串为"10"时满足条件
    #     ((2, 3), lambda v: v != "01"),  # 子句2：索引子集为(2, 3)，位串为"01"时满足条件
    #     ((1, 2), lambda v: v in ["01", "00"])  # 子句3：索引子集为(1, 2)，位串为"01"或"00"时满足条件
    # ]

    f = [
        ((0,), lambda v: v == "1"),  # 子句1：索引子集为(0, 1)，位串为"10"时满足条件
        # ((1), lambda v: v == "1")
    ]
    # 随机生成一些子句
    # print(f)
    # k = 1
    # condition_str =[''.join([str(random.randint(0, 1)) for _ in range(t)]) for _ in range(k)]
    # print(condition_str)
    # f = [(tuple(random.sample(range(l), t)), lambda v: v == condition_str[i])  for i in range(k)]

    # print(f)
  # 固定随机种子以便复现结果
    # num_clauses = 2  # 生成的子句数量
    # f = []
    # for _ in range(num_clauses):
    #     Ti = tuple(random.sample(range(l), t))
    #     fi = lambda v: random.choice([0, 1])
    #     f.append((Ti, fi))

    # print("策略 f:", f)
    
    # 生成受限密钥
    sk_f = cprf.Constrain(f)
    
    # 多个 x 测试
    # test_xs = ["1010","1111"]
    # test_xs = ["1010", "1111", "0000", "0101", "0011"]
    # test_xs = ["0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]
    test_xs = [''.join(bits) for bits in itertools.product('01', repeat=l)]
    #
    for x in test_xs:
        # 检查 x 是否满足策略
        S_x = cprf._get_subsets(x)
        print("s_x", S_x)
        satisfies_policy = True
        for Ti, fi in f:
            print("Ti, fi", Ti, fi)
            subset_v = next((v for T, v in S_x if T == Ti), None)
            print("subset_v", subset_v)
            print("subset_v is None", subset_v is None)
            print("not fi(subset_v)", not fi(subset_v))
            if subset_v is None or not fi(subset_v):

                satisfies_policy = False
                break
        
        # 评估 PRF 和受限 PRF
        prf_result = cprf.Eval(x)
        constrained_prf_result = cprf.Eval_sk(sk_f, x)
        prf_matches = prf_result == constrained_prf_result
        
        # 输出结果
        print(f"x: {x}, 满足策略: {satisfies_policy}, PRF结果与受限PRF结果相同: {prf_matches}, PRF结果: {bin(prf_result)}, 受限PRF结果: {bin(constrained_prf_result)}")
