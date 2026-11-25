import pandas as pd
df = pd.read_csv(r"D:\network-forensics\friday.csv")
df.columns = df.columns.str.strip()

df['Packet_Rate'] = df['Total Fwd Packet'] / (df['Flow Duration'] + 1)
print(df.groupby('Label')['Packet_Rate'].describe())