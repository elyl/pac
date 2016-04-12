def primes():
    """Générateur infini de tous les nombres premiers.
    >>> for p in primes():
    ...     print(p)
    ...     if p > 100:
    ...         break
    2
    3
    5
    7
    11
    13
    17
    19
    23
    29
    31
    37
    41
    43
    47
    53
    59
    61
    67
    71
    73
    79
    83
    89
    97
    101
    """
    yield 2 # 2 est le seul nombre premier PAIR
    D = {}  # D[n] = 2*p ---> p est le plus petit facteur premier de n
    q = 3   # nombre (impair) dont on teste la primalité
    while True:
        two_p = D.pop(q, None)  # connait-on un nombre premier qui divise q ?
        if two_p:               # OUI : q n'est pas premier, car p le divise.
            # assert q % (two_p // 2) == 0
            x = q + two_p           # Pour maintenir le dictionnaire D, on
            while x in D:           # cherche le prochain multiple (impair) de
                x += two_p          # p qui n'a pas de diviseurs inférieurs à
            D[x] = two_p            # p, et marquer qu'il est divisible par p.
                                    # astuce : q et p sont impair, donc q+p est
                                    #     pair. On passe donc directement à
                                    #     q + 2p. 
        else:                   # NON : q est premier.
            D[q*q] = 2*q        # q*q est le plus petit nombre composite qui n'a
                                # pas de facteurs plus petits que q
            yield q             # Renvoie q
        q += 2


if __name__ == "__main__":
    # speed test
    from time import clock
    t = clock()
    for p in primes():
        if p > 1e7:
            break
    print(clock() - t)