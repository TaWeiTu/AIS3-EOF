#include <cassert>
#include <cstring>
#include <stack>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "aes.h"

uint8_t Parse(char x) {
  assert((x >= '0' && x <= '9') || (x >= 'a' || x <= 'f'));
  if (x >= '0' && x <= '9') return x - '0';
  else return 10 + x - 'a';
}

uint8_t ReadByte(std::ifstream &ifs) {
  char a = ifs.get();
  char b = ifs.get();
  return Parse(a) * 16 + Parse(b);
}

uint32_t ReadBytes(int num_bytes, std::ifstream &ifs) {
  uint32_t res = 0;
  for (int i = 0; i < num_bytes; ++i) {
    uint8_t byte = ReadByte(ifs);
    res |= uint32_t(byte) << (8 * i);
  }
  return res;
}

struct File {
  int value, pad;
  std::string filename;
  std::vector<File *> child;
  std::string content;
  File *parent;
};

File *NewFile(std::ifstream &ifs, File *parent) {
  File *f = new File();
  f->parent = parent;
  ifs.read(reinterpret_cast<char *>(&f->value), 4);
  int num_byte = 0;
  ifs.read(reinterpret_cast<char *>(&num_byte), 2);
  f->filename.resize(num_byte);
  ifs.read(const_cast<char *>(f->filename.data()), num_byte);
  ifs.read(reinterpret_cast<char *>(&num_byte), 4);
  f->content.resize(num_byte);
  ifs.read(const_cast<char *>(f->content.data()), num_byte);
  return f;
}

void Decrypt(File *file) {
  std::vector<uint8_t> buffer(file->content.size());
  for (int i = 0; i < file->content.size(); ++i) buffer[i] = file->content[i];
  AES_ctx *ctx = new AES_ctx();
  uint8_t key[32] = {-23, 49,  -33,  -64, -61,  122, -18, -84,
                     110, -55, -121, 28,  -118, 122, -10, -20};
  uint8_t iv[32] = {-95,  -92, -60, 28, 28, 91, -59, 46,
                    -112, -38, -72, -2, 70, 35, -65, -69};
  AES_init_ctx_iv(ctx, key, iv);
  AES_CBC_encrypt_buffer(ctx, buffer.data(), file->content.size());
  std::string out;
  for (int i = 0; i < file->content.size(); ++i) out += buffer[i];
  if (out.substr(0, 4) == "FLAG") std::cout << out << "\n";
}

int main() {
  std::ifstream ifs("dump3");
  char buf[10];
  ifs.read(buf, 8);
  assert(strcmp(buf, "hackerFS") == 0);
  ifs.read(buf, 8);
  std::stack<int> stk;

  File *root = NewFile(ifs, nullptr);
  File *cur_file = root;
  int num_file = 0;
  ifs.read(reinterpret_cast<char *>(&num_file), 4);
  while (true) {
    int v = !stk.empty() || num_file;
    if (!v) break;
    if (num_file) {
      File *new_file = NewFile(ifs, cur_file);
      --num_file;
      stk.push(num_file);
      ifs.read(reinterpret_cast<char *>(&num_file), 4);
      cur_file->child.push_back(new_file);
      cur_file = new_file;
    } else {
      cur_file = cur_file->parent;
      if (!stk.empty()) {
        num_file = stk.top();
        stk.pop();
      }
    }
  }

  auto Dfs = [&](auto dfs, File *file) -> void {
    for (File *ch : file->child) dfs(dfs, ch);
    if (file->value == 1) Decrypt(file);
  };

  Dfs(Dfs, root);
}
