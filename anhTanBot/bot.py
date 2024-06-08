import asyncio
from time import sleep
import discord
# from discord import app_commands 
from discord.ext import commands
import discord.ext.commands
import dotenv
import os
import colorama

import discord.ext

# import discord.ext

dotenv.load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
description = '''Một anh Tân người máy'''

intents = discord.Intents.all()
# intents.members = True
# intents.message_content = True

DEBUG = False
stop_check_class = False

delay_time_at_diemdanh = 300 # 5 phut
delete_after_at_diemdanh = 200

'''
# class MyClient(discord.Client):
#     def __init__(self, *, intents: discord.Intents):
#         super().__init__(intents=intents)
#         # A CommandTree is a special type that holds all the application command
#         # state required to make it work. This is a separate class because it
#         # allows all the extra state to be opt-in.
#         # Whenever you want to work with application commands, your tree is used
#         # to store and work with them.
#         # Note: When using commands.Bot instead of discord.Client, the bot will
#         # maintain its own tree instead.
#         self.tree = app_commands.CommandTree(self)

#     # In this basic example, we just synchronize the app commands to one guild.
#     # Instead of specifying a guild to every command, we copy over our global commands instead.
#     # By doing so, we don't have to wait up to an hour until they are shown to the end-user.
#     async def setup_hook(self):
#         # This copies the global commands over to your guild.
#         # self.tree.copy_global_to(guild=902626872725217301)
#         await self.tree.sync(guild=902626872725217301)
# bot = MyClient(intents=intents)
'''
bot = commands.Bot(command_prefix="/", description=description, intents=intents)

'''
@bot.tree.command(name="diemdanh", description="Điểm danh các học viên có mặt trong channel hiện tại")
async def diem_danh(interaction: discord.Interaction):
    """Điểm danh lớp: diem_danh [tên kênh không dấu]"""
    global stop_check_class
    list_user_id:list = load_file_user(class_name=interaction.channel.name)
    print(interaction.channel_id)
    print(interaction.guild_id)
    list_user_comat:list = []
    while len(list_user_id) != 0 and stop_check_class is False:
        output_message = "Có mặt: \n"
        output_message += "".join(f"- {user}\n" for user in list_user_comat)
        current_members_of_channel = interaction.channel.members
        for person in current_members_of_channel:
            if not person.bot:
                if person.display_name in list_user_id:
                    output_message += f"- {person.display_name}\n"
                    list_user_id.remove(person.display_name)
                    list_user_comat.append(person.display_name)
        output_message += absent_user_string(list_user_id) 
        if DEBUG:
            await interaction.response.send_message(delete_after=2,content=output_message, ephemeral=True, silent=True)
            sleep(3) # stop at 5 minuts = 300
        else: 
            await interaction.response.send_message(delete_after=delete_after_at_diemdanh,content=output_message, ephemeral=True, silent=True)
            sleep(delay_time_at_diemdanh) # stop at 5 minuts = 300

@bot.tree.command(name="dung_diem_danh", description="Dừng diểm danh các học viên có mặt trong channel hiện tại")
async def dung_diem_danh(interaction: discord.Interaction):
    global stop_check_class
    stop_check_class = True
    await interaction.response("Anh Tân machine đã dừng điểm danh!")
'''
def load_file_user(class_name: str) -> list:
    danh_sach_file_path = class_name + ".txt"
    print(f"class name: {class_name} --> file: {danh_sach_file_path}")
    try:
        with open(danh_sach_file_path, "r", encoding="UTF8") as read_class_user:
            class_user_id = read_class_user.readlines()
            return [user_name.strip().strip("\n") for user_name in class_user_id]
    except FileNotFoundError as e:
        print(f"{colorama.Fore.RED}Lỗi load file danh sách lớp!{colorama.Fore.RESET}")
        return [-1]
    except Exception as e:
        print(f"Error: {e}")
        return [-2] 


def absent_user_string(list_remainer_user:list)->str:
    '''Trả về 1 chuỗi các học viên còn vắng'''
    output = "Chưa có mặt: \n"
    for i in list_remainer_user:
        output += f"- {i}\n"
    return output

# '''  
@bot.command()
async def diem_danh(ctx: discord.ext.commands.Context):
    """Điểm danh lớp: diem_danh [tên kênh không dấu]"""
    global stop_check_class
    stop_check_class = False
    list_user_id:list = load_file_user(ctx.channel.name)
    if list_user_id == [-1]: # handle lỗi chưa có file danh sách
        await ctx.reply("Chưa có danh sách lớp !", ephemeral=True)
    elif list_user_id == [-2]: # handle các lỗi khác
        await ctx.reply("Có một số lỗi khác, xem terminal để xác định rõ!", ephemeral=True)
    else: # không lỗi khác
        # print(ctx.channel.id)
        # print(ctx.guild.id)
        list_user_comat:list = []
        while len(list_user_id) != 0 and stop_check_class is False:
            output_message = "Có mặt: \n"
            output_message += "".join(f"- {user}\n" for user in list_user_comat)
            current_members_of_channel = ctx.channel.members
            for person in current_members_of_channel:
                # print (f"{colorama.Fore.CYAN} [+] Kiểm tra bạn học: {person.display_name} {colorama.Fore.RESET}")
                if not person.bot:
                    if person.display_name in list_user_id:
                        output_message += f"- {person.display_name}\n"
                        list_user_id.remove(person.display_name)
                        list_user_comat.append(person.display_name)
                    else:
                        print(person.display_name)
            output_message += absent_user_string(list_user_id) 
            if DEBUG:
                await ctx.reply(delete_after=2,content=output_message, ephemeral=True, silent=True)
                # await asyncio.sleep(3) # stop at 5 minuts = 300
                # print("stop")
                # count = 0
                # while count < delay_time_at_diemdanh and stop_check_class is False:
                #     await asyncio.sleep(3)
                #     count += 3
            else: 
                await ctx.reply(delete_after=delete_after_at_diemdanh,content=output_message, ephemeral=True, silent=True)
                await asyncio.sleep(delay_time_at_diemdanh) # stop at 5 minuts = 300
                print("stop")
                # count = 0
                # while count < delay_time_at_diemdanh and stop_check_class is False:
                #     await asyncio.sleep(3)
                #     count += 3


@bot.command()
async def dung_diem_danh(ctx):
    global stop_check_class
    stop_check_class = True
    await ctx.reply("Anh Tân machine đã dừng điểm danh!")
# '''

@bot.event
async def on_ready():
    # for server in bot.guilds:
    #     print("sync = " + str(server.id))
    #     await bot.tree.sync(guild=discord.Object(id=server.id))
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print('------')


def main():
    bot.run(str(TOKEN))
    
main()
