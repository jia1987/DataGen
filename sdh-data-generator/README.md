# SDH Data Generator

## 项目简介
该项目是一个SDH数据生成程序，旨在根据ITU-T G.707协议，将PCAP文件中的以太网数据映射到SDH指定虚容器，并生成标准SDH帧结构数据的.dat文件。

## 文件结构
```
sdh-data-generator
├── src
│   ├── main.py          # 程序入口点，初始化GUI并启动应用程序
│   ├── gui.py           # 定义图形用户界面，提供选择PCAP文件的功能
│   ├── sdh_encoder.py    # 实现SDH编码逻辑，生成标准SDH帧结构数据
│   ├── pcap_parser.py    # 解析PCAP文件，提取以太网数据包
│   └── utils
│       └── __init__.py  # 初始化utils模块，包含辅助函数或常量
├── requirements.txt      # 列出项目所需的Python库和依赖项
├── README.md             # 项目文档，介绍如何使用程序及其功能
└── dat                   # 存放生成的标准SDH帧结构数据的.dat文件
```

## 使用说明
1. 确保已安装Python环境。
2. 在项目根目录下，使用以下命令安装所需依赖：
   ```
   pip install -r requirements.txt
   ```
3. 运行程序：
   ```
   python src/main.py
   ```
4. 在图形用户界面中，选择要处理的PCAP文件。
5. 点击生成按钮，程序将处理文件并生成相应的.dat文件，存放在`dat`目录中。

## 贡献
欢迎任何形式的贡献！请提交问题或拉取请求以帮助改进项目。