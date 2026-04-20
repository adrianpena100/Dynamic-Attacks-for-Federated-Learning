import torch
from pytorchexample.task import load_centralized_dataset, get_task_from_run_config

spec, model_factory = get_task_from_run_config({"dataset": "flwrlabs/femnist"})
print(sum(p.numel() for p in model_factory().parameters()), "params")
for rs, bs in [(620,32),(620,620),(1860,32)]:
    ld = load_centralized_dataset(dataset="flwrlabs/femnist",eval_split="train",batch_size=bs,max_eval_examples=rs)
    m = model_factory(); m.train()
    gsd = {k:v.clone() for k,v in m.state_dict().items()}
    o = torch.optim.SGD(m.parameters(),lr=0.1)
    cr = torch.nn.CrossEntropyLoss(); st=0
    for b in ld:
        o.zero_grad(); cr(m(b["img"]),b["label"]).backward(); o.step(); st+=1
    sf = torch.cat([(m.state_dict()[k].float()-gsd[k].float()).flatten() for k in gsd])
    print(f"root={rs} bs={bs} steps={st} srv_norm={torch.norm(sf):.4f}")
