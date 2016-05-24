class mrand48:
    def srand48(self, seed):
        self.rand48_state = 0x330e + (seed << 16)
        self.rand48_state &= 0xffffffffffffffff

    def mrand48(self):
        self.rand48_state = (0x00000005deece66d * self.rand48_state + 11) & 0x0000ffffffffffff;
        return (self.rand48_state >> 16) & 0xffffffff;
