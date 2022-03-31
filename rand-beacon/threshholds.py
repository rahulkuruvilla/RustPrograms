

calc_n = lambda f: 3*f
calc_t = lambda n, f: n-f

faulty_nodes = range(1, 50)
fs = [f_i for f_i in faulty_nodes]
ns = [n_i for n_i in map(calc_n, faulty_nodes)]
ts = [t_i for t_i in map(calc_t, ns, fs)]

print(fs)
print(ns)
print(ts)
for index in range(len(faulty_nodes)):
    print("(f,n,t) = ({},{},{})".format(fs[index], ns[index], ts[index]))