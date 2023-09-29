from pdb import set_trace
import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader
import pandas as pd

def int256_to_floats(int256_val):
    floats = []
    mask = (1 << 32) - 1
    for n in range(8):
        segment = (int256_val >> (n * 32)) & mask
        floats.append(segment / float(2**32))
    return floats

N=2048
class TokenGenerator(nn.Module):
    def __init__(self):
        super().__init__()
        input_size = 16 # 8segFloat X and Y
        output_size = 16
        self.layers = nn.Sequential(
            nn.Linear(input_size, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, output_size),
            nn.Softmax(dim=1) # Token = t
        )

    def forward(self, x):
        return self.layers(x)

class Recoverer(nn.Module):
    def __init__(self):
        super().__init__()
        input_size = 16 + 16 + 16 # K0xy|K1xy|t
        output_size = 2 # RecoveryBit
        self.layers = nn.Sequential(
            nn.Linear(input_size, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, N),
            nn.ReLU(),
            nn.Linear(N, output_size),
            nn.Softmax(dim=1)
        )

    def forward(self, x):
        return self.layers(x)

class Combined(nn.Module):
    def __init__(self):
        super().__init__()
        self.mg = TokenGenerator()
        self.mr = Recoverer()

    def forward(self, i1, i2):
        token = self.mg(i1)
        input_rec = torch.cat((i2, token), dim=1)
        return self.mr(input_rec)

    def save(self):
        torch.save(self.mg.state_dict(), 'generator.pth')
        torch.save(self.mr.state_dict(), 'recoverer.pth')

    def load(self):
        self.mg.load_state_dict(torch.load('generator.pth'))
        #self.mg.eval()
        self.mr.load_state_dict(torch.load('recoverer.pth'))
        #self.mr.eval()

class CSVDataset(Dataset):
    def __init__(self, csv_file):
        self.data = pd.read_csv(csv_file)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        row = self.data.iloc[idx]
        pk = torch.tensor(row[0:16].values, dtype=torch.float32)
        pks = torch.tensor(row[16:48].values, dtype=torch.float32)
        r = torch.tensor(row[48:50].values, dtype=torch.float32)
        return pk, pks, r



if __name__ == '__main__':
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = Combined()
    model.to(device)
    # model.load()

    # Combined/GPU Friendly Training
    dataset = CSVDataset('./train.csv')
    dataloader = DataLoader(dataset, batch_size=2048, shuffle=True)

    model.train() # Re-enable dropout and other tweaks
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.MSELoss()

    for i1, i2, targets in dataloader:
        i1, i2, targets = i1.to(device), i2.to(device), targets.to(device)
        optimizer.zero_grad()
        outputs = model(i1, i2)
        loss = loss_fn(outputs, targets)
        loss.backward()
        optimizer.step()
        print(f"Batch done, loss {loss.item() :.2f}")

    # Evaluate
    model.eval()
    model.save()
    print("Evaluating")
    dataset = CSVDataset('./test.csv')
    dataloader = DataLoader(dataset, batch_size=1024, shuffle=True)
    for i1, i2, targets in dataloader:
        i1, i2, targets = i1.to(device), i2.to(device), targets.to(device)
        outputs = model(i1, i2)
        loss = loss_fn(outputs, targets)
        print(f"Eval done, loss {loss.item() :.2f}")

