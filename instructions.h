

#define min(a,b) ((a) < (b) ? (a) : (b))



void PacketBuildInstructionsFree(PacketBuildInstructions **list);
AS_attacks *InstructionsToAttack(AS_context *, PacketBuildInstructions *instructions, int count, int interval);
PacketBuildInstructions *InstructionsFindConnection(PacketBuildInstructions **instructions, FilterInformation *flt);
PacketBuildInstructions *PacketsToInstructions(PacketInfo *packets);
int GenerateTCP4CloseConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client);
int GenerateTCP4SendDataInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client, char *data, int size);
int GenerateTCP4ConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list);
PacketBuildInstructions *BuildInstructionsNew(PacketBuildInstructions **list, uint32_t source_ip, uint32_t destination_ip, int source_port, int dst_port, int flags, int ttl, int window_size);
int FilterCheck(FilterInformation *fptr, PacketBuildInstructions *iptr);
void FilterPrepare(FilterInformation *fptr, int type, uint32_t value);

PacketBuildInstructions *ThreadedInstructionsFindConnection(AS_context *, PacketBuildInstructions **instructions, FilterInformation *flt, int threads, int replay_count, int interval);