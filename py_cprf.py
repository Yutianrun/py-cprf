import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from itertools import combinations

class AES_cPRF:
    def __init__(self, t, l):
        """
        初始化AES_cPRF类。
        :param t: 子集的大小 (CNF locality)
        :param l: 输入长度的上限
        """
        self.t = t
        self.l = l
        self.msk = None
        self.pp = None
        
    def Setup(self):
        """
        生成公共参数 (pp) 和主密钥 (msk)。
        """
        # self.msk = os.urandom(16)  # 生成128位AES密钥
        seed = 'cprf'
        self.msk = hashlib.sha256(seed.encode()).digest()
        self.pp = None             # 公共参数 (此示例中未使用)
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
        S_x = self._get_subsets(x)
        print('S_x', S_x)
        result = 0
        
        for T, v in S_x:
            # 生成子密钥 sk_T_v
            sk_T_v = AES.new(self.msk, AES.MODE_ECB).encrypt(pad(str(T).encode() + v.encode(), 16))
            # 使用子密钥评估AES并异或结果
            result ^= int.from_bytes(AES.new(sk_T_v, AES.MODE_ECB).encrypt(pad(x.encode(), 16)), 'big')
        return result
    
    def Constrain(self, f):
        """
        生成受限密钥。
        :param f: CNF子句集合，每个子句为(Ti, fi)
        :return: 受限密钥 sk_f
        """
        Sf_i = []
        all_subsets = []

        for s in ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']:
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
        for i in range(0, len(Sf), 5):
            print(Sf[i:i+5])

        # 生成受限密钥
        sk_f = {}
        for T, v in Sf:
            sk_f[(T, v)] = AES.new(self.msk, AES.MODE_ECB).encrypt(pad(str(T).encode() + v.encode(), 16))
        
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
                result ^= int.from_bytes(AES.new(sk_T_v, AES.MODE_ECB).encrypt(pad(x.encode(), 16)), 'big')
        
        return result

# 使用示例
# ...existing code...
# 使用示例
if __name__ == "__main__":

    t = 2  # 子集的大小
    l = 4  # 输入长度
    cprf = AES_cPRF(t, l)
    
    # 设置阶段
    pp, msk = cprf.Setup()
    print("Master Secret Key (msk):", msk.hex())
    
    # 定义策略 f
    f = [
        ((0, 1), lambda v: v == "10"),  # 子句1：索引子集为(0, 1)，位串为"10"时满足条件
        ((2, 3), lambda v: v != "01"),  # 子句2：索引子集为(2, 3)，位串为"01"时满足条件
        ((1, 2), lambda v: v in ["01", "00"])  # 子句3：索引子集为(1, 2)，位串为"01"或"00"时满足条件
    ]
    
    # 生成受限密钥
    sk_f = cprf.Constrain(f)
    
    # 多个 x 测试
    test_xs = ["1010", "1111", "0000", "0101", "0011"]
    # test_xs = ["0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]
    
    for x in test_xs:
        # 检查 x 是否满足策略
        S_x = cprf._get_subsets(x)
        satisfies_policy = True
        for Ti, fi in f:
            subset_v = next((v for T, v in S_x if T == Ti), None)
            if subset_v is None or not fi(subset_v):
                satisfies_policy = False
                break
        
        # 评估 PRF 和受限 PRF
        prf_result = cprf.Eval(x)
        constrained_prf_result = cprf.Eval_sk(sk_f, x)
        prf_matches = prf_result == constrained_prf_result
        
        # 输出结果
        print(f"x: {x}, 满足策略: {satisfies_policy}, PRF结果与受限PRF结果相同: {prf_matches}, PRF结果: {prf_result}, 受限PRF结果: {constrained_prf_result}")
