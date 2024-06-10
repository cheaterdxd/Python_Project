from typing import Optional

import discord
from discord import app_commands
import colorama, asyncio
import yaml
import traceback

DEBUG = False
if DEBUG:
    MY_GUILD = discord.Object(id=902626872725217301)  # test guild
else:
    MY_GUILD = discord.Object(id=868410572369174539) # Trung tâm Chí Dũng guild

class MyClient(discord.Client):
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        # A CommandTree is a special type that holds all the application command
        # state required to make it work. This is a separate class because it
        # allows all the extra state to be opt-in.
        # Whenever you want to work with application commands, your tree is used
        # to store and work with them.
        # Note: When using commands.Bot instead of discord.Client, the bot will
        # maintain its own tree instead.
        self.tree = app_commands.CommandTree(self)

    # In this basic example, we just synchronize the app commands to one guild.
    # Instead of specifying a guild to every command, we copy over our global commands instead.
    # By doing so, we don't have to wait up to an hour until they are shown to the end-user.
    async def setup_hook(self):
        # This copies the global commands over to your guild.
        self.tree.copy_global_to(guild=MY_GUILD)
        await self.tree.sync(guild=MY_GUILD)


intents = discord.Intents.default()
client = MyClient(intents=intents)
stop_check_class = False

delay_time_at_diemdanh = 300 # 5 phut
delete_after_at_diemdanh = 200
danh_sach_hoc_vien_path = "class.yaml"


def load_file_user(class_name: str) -> list:
    '''Load data for class name '''
    global danh_sach_hoc_vien_path
    try:
        with open(danh_sach_hoc_vien_path, "r", encoding="UTF8") as read_class_user:
            data = yaml.safe_load_all(read_class_user)
            for i in data: 
                print(i[class_name])
                if(i[class_name]):
                    print("found")
                    class_users = i[class_name]
                    return [user_name.strip().strip("\n") for user_name in class_users]
                else:
                    return [-1]
    except FileNotFoundError as e:
        print(f"{colorama.Fore.RED}Lỗi load file danh sách lớp!{colorama.Fore.RESET}")
        return [-1]
    except KeyError as e:
        print(f"{colorama.Fore.RED}Danh sách chưa có lớp này!{colorama.Fore.RESET}")
        return [-2]
    except Exception as e:
        print(f"Error:\n{e}")
        traceback.print_exc()
        return [-3]


def absent_user_string(list_remainer_user:list)->str:
    '''Trả về 1 chuỗi các học viên còn vắng'''
    output = "Chưa có mặt: \n"
    for i in list_remainer_user:
        output += f"- {i}\n"
    return output

@client.event
async def on_ready():
    print(f'Logged in as {client.user} (ID: {client.user.id})')
    print('------')

@client.tree.command()
async def diem_danh(interaction: discord.Interaction):
    """Điểm danh lớp: diem_danh [tên kênh không dấu]"""
    global stop_check_class
    stop_check_class = False
    list_user_id:list = load_file_user(interaction.channel.name)
    if list_user_id == [-1]: # handle lỗi chưa có file danh sách
        await interaction.response.send_message("Không tìm thấy file class.yaml", ephemeral=True)
    elif list_user_id == [-2]: # handle các lỗi khác
        await interaction.response.send_message("Không tìm thấy lớp trong file class.yaml", ephemeral=True)
    elif list_user_id == [-3]: # handle các lỗi khác
        await interaction.response.send_message("Tồn tại lỗi khác, xem terminal để kiểm tra lỗi", ephemeral=True)
    else: # không lỗi khác
        # print(ctx.channel.id)
        # print(ctx.guild.id)
        list_user_comat:list = []
        while len(list_user_id) != 0 and stop_check_class is False:
            output_message = "Có mặt: \n"
            output_message += "".join(f"- {user}\n" for user in list_user_comat)
            current_members_of_channel = interaction.channel.members
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
                await interaction.response.send_message(delete_after=2,content=output_message, ephemeral=True, silent=True)
            else: 
                print(interaction.channel.name)
                await interaction.response.send_message(delete_after=delete_after_at_diemdanh,content=output_message, ephemeral=True, silent=True)
                await asyncio.sleep(delay_time_at_diemdanh) # stop at 5 minuts = 300

@client.tree.command()
async def dung_diem_danh(interaction: discord.Interaction):
    global stop_check_class
    stop_check_class = True
    await interaction.response.send_message("Anh Tân machine đã dừng điểm danh!", ephemeral=True)

'''

@client.tree.command()
async def hello(interaction: discord.Interaction):
    """Says hello!"""
    await interaction.response.send_message(f'Hi, {interaction.user.mention}', ephemeral=True)


@client.tree.command()
@app_commands.describe(
    first_value='The first value you want to add something to',
    second_value='The value you want to add to the first value',
)
async def add(interaction: discord.Interaction, first_value: int, second_value: int):
    """Adds two numbers together."""
    await interaction.response.send_message(f'{first_value} + {second_value} = {first_value + second_value}')


# The rename decorator allows us to change the display of the parameter on Discord.
# In this example, even though we use `text_to_send` in the code, the client will use `text` instead.
# Note that other decorators will still refer to it as `text_to_send` in the code.
@client.tree.command()
@app_commands.rename(text_to_send='text')
@app_commands.describe(text_to_send='Text to send in the current channel')
async def send(interaction: discord.Interaction, text_to_send: str):
    """Sends the text into the current channel."""
    await interaction.response.send_message(text_to_send)


# To make an argument optional, you can either give it a supported default argument
# or you can mark it as Optional from the typing standard library. This example does both.
@client.tree.command()
@app_commands.describe(member='The member you want to get the joined date from; defaults to the user who uses the command')
async def joined(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    """Says when a member joined."""
    # If no member is explicitly provided then we use the command user here
    member = member or interaction.user

    # The format_dt function formats the date time into a human readable representation in the official client
    await interaction.response.send_message(f'{member} joined {discord.utils.format_dt(member.joined_at)}')


# A Context Menu command is an app command that can be run on a member or on a message by
# accessing a menu within the client, usually via right clicking.
# It always takes an interaction as its first parameter and a Member or Message as its second parameter.

# This context menu command only works on members
@client.tree.context_menu(name='Show Join Date')
async def show_join_date(interaction: discord.Interaction, member: discord.Member):
    # The format_dt function formats the date time into a human readable representation in the official client
    await interaction.response.send_message(f'{member} joined at {discord.utils.format_dt(member.joined_at)}')


# This context menu command only works on messages
@client.tree.context_menu(name='Report to Moderators')
async def report_message(interaction: discord.Interaction, message: discord.Message):
    # We're sending this response message with ephemeral=True, so only the command executor can see it
    await interaction.response.send_message(
        f'Thanks for reporting this message by {message.author.mention} to our moderators.', ephemeral=True
    )

    # Handle report by sending it into a log channel
    log_channel = interaction.guild.get_channel(0)  # replace with your channel id

    embed = discord.Embed(title='Reported Message')
    if message.content:
        embed.description = message.content

    embed.set_author(name=message.author.display_name, icon_url=message.author.display_avatar.url)
    embed.timestamp = message.created_at

    url_view = discord.ui.View()
    url_view.add_item(discord.ui.Button(label='Go to Message', style=discord.ButtonStyle.url, url=message.jump_url))

    await log_channel.send(embed=embed, view=url_view)
'''

# client.run('')