import tkinter as tk
from tkinter import filedialog, messagebox
from pcap_parser import PcapParser
from sdh_encoder import SDHEncoder

class SDHDataGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("SDH Data Generator")

        self.label = tk.Label(master, text="选择PCAP文件:")
        self.label.pack()

        self.select_button = tk.Button(master, text="选择文件", command=self.select_file)
        self.select_button.pack()

        self.generate_button = tk.Button(master, text="生成SDH数据", command=self.generate_sdh_data)
        self.generate_button.pack()

        self.file_path = None

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if self.file_path:
            messagebox.showinfo("选择文件", f"已选择文件: {self.file_path}")

    def generate_sdh_data(self):
        if not self.file_path:
            messagebox.showwarning("警告", "请先选择一个PCAP文件。")
            return

        try:
            parser = PcapParser(self.file_path)
            ethernet_data = parser.parse()

            encoder = SDHEncoder()
            sdh_data = encoder.encode(ethernet_data)

            output_file = f"dat/sdh_output.dat"
            with open(output_file, 'wb') as f:
                f.write(sdh_data)

            messagebox.showinfo("成功", f"SDH数据已生成并保存到: {output_file}")
        except Exception as e:
            messagebox.showerror("错误", f"生成SDH数据时出错: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SDHDataGeneratorApp(root)
    root.mainloop()