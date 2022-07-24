
flag = ["a" for i in range(32)]

flag[:5] = 'hope{'
flag[-1] = '}'
flag[5::3] = 'i0_tnl3a0'
flag[4::4] = '{0p0lsl'
flag[3::5] = 'e0y_3l'
flag[6::3] = '_vph_is_t'
flag[7::3] = 'ley0sc_l}'

print('flag is: ', "".join(flag))
