from tkinter import Tk, Button, Label, filedialog, messagebox
import os
from sdh_encoder import encode_sdh_data
from pcap_parser import parse_pcap

class SDHDataGeneratorGUI:
    def __init__(self, master):
        self.master = master
        master.title("SDH Data Generator")

        self.label = Label(master, text="选择PCAP文件以生成SDH数据")
        self.label.pack()

        self.select_button = Button(master, text="选择PCAP文件", command=self.select_file)
        self.select_button.pack()

        self.generate_button = Button(master, text="生成SDH数据", command=self.generate_sdh_data)
        self.generate_button.pack()

        self.file_path = ""

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if self.file_path:
            self.label.config(text=os.path.basename(self.file_path))

    def generate_sdh_data(self):
        if not self.file_path:
            messagebox.showerror("错误", "请先选择一个PCAP文件")
            return
        
        try:
            ethernet_data = parse_pcap(self.file_path)
            sdh_data = encode_sdh_data(ethernet_data)
            output_file = os.path.join("dat", "output.sdh.dat")
            with open(output_file, "wb") as f:
                f.write(sdh_data)
            messagebox.showinfo("成功", f"SDH数据已生成: {output_file}")
        except Exception as e:
            messagebox.showerror("错误", f"生成SDH数据时出错: {str(e)}")

if __name__ == "__main__":
    root = Tk()
    gui = SDHDataGeneratorGUI(root)
    root.mainloop()