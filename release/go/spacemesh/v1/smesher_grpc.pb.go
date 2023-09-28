// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: spacemesh/v1/smesher.proto

package spacemeshv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SmesherService_IsSmeshing_FullMethodName            = "/spacemesh.v1.SmesherService/IsSmeshing"
	SmesherService_StartSmeshing_FullMethodName         = "/spacemesh.v1.SmesherService/StartSmeshing"
	SmesherService_StopSmeshing_FullMethodName          = "/spacemesh.v1.SmesherService/StopSmeshing"
	SmesherService_SmesherID_FullMethodName             = "/spacemesh.v1.SmesherService/SmesherID"
	SmesherService_Coinbase_FullMethodName              = "/spacemesh.v1.SmesherService/Coinbase"
	SmesherService_SetCoinbase_FullMethodName           = "/spacemesh.v1.SmesherService/SetCoinbase"
	SmesherService_MinGas_FullMethodName                = "/spacemesh.v1.SmesherService/MinGas"
	SmesherService_SetMinGas_FullMethodName             = "/spacemesh.v1.SmesherService/SetMinGas"
	SmesherService_EstimatedRewards_FullMethodName      = "/spacemesh.v1.SmesherService/EstimatedRewards"
	SmesherService_PostSetupStatus_FullMethodName       = "/spacemesh.v1.SmesherService/PostSetupStatus"
	SmesherService_PostSetupStatusStream_FullMethodName = "/spacemesh.v1.SmesherService/PostSetupStatusStream"
	SmesherService_PostSetupProviders_FullMethodName    = "/spacemesh.v1.SmesherService/PostSetupProviders"
	SmesherService_PostConfig_FullMethodName            = "/spacemesh.v1.SmesherService/PostConfig"
	SmesherService_UpdatePoetServers_FullMethodName     = "/spacemesh.v1.SmesherService/UpdatePoetServers"
)

// SmesherServiceClient is the client API for SmesherService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SmesherServiceClient interface {
	// Returns true iff node is currently smeshing
	IsSmeshing(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IsSmeshingResponse, error)
	// Starts smeshing, after completing the post setup.
	// Changing of the post setup options (e.g., number of units), after initial setup, is supported.
	// Returns success if request is accepted by node , failure if it fails
	StartSmeshing(ctx context.Context, in *StartSmeshingRequest, opts ...grpc.CallOption) (*StartSmeshingResponse, error)
	// Stops smeshing, or the preceding post setup session, and optionally attempt to
	// delete the post setup data files(s).
	// Returns success if request is accepted by node, failure if it fails
	StopSmeshing(ctx context.Context, in *StopSmeshingRequest, opts ...grpc.CallOption) (*StopSmeshingResponse, error)
	// Get the current smesher id generated by the node
	SmesherID(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SmesherIDResponse, error)
	// Get the current coinbase
	Coinbase(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*CoinbaseResponse, error)
	// Set the coinbase
	// Returns success if request succeeds, failure if it fails
	SetCoinbase(ctx context.Context, in *SetCoinbaseRequest, opts ...grpc.CallOption) (*SetCoinbaseResponse, error)
	// Get the current min gas for including txs in blocks by this smesher
	MinGas(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*MinGasResponse, error)
	// Set a min gas units for including txs in blocks by this smesher
	// Returns success if request succeeds, failure if it fails
	SetMinGas(ctx context.Context, in *SetMinGasRequest, opts ...grpc.CallOption) (*SetMinGasResponse, error)
	// Estimate smeshing rewards over the next upcoming epoch
	EstimatedRewards(ctx context.Context, in *EstimatedRewardsRequest, opts ...grpc.CallOption) (*EstimatedRewardsResponse, error)
	// Returns the Post setup status
	PostSetupStatus(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*PostSetupStatusResponse, error)
	// Returns a stream of updates for the Post setup status
	PostSetupStatusStream(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (SmesherService_PostSetupStatusStreamClient, error)
	// Returns a list of available Post setup providers
	PostSetupProviders(ctx context.Context, in *PostSetupProvidersRequest, opts ...grpc.CallOption) (*PostSetupProvidersResponse, error)
	// Returns the Post protocol config
	PostConfig(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*PostConfigResponse, error)
	// UpdatePoetServers updates poet servers
	// All existing PoET servers will be substituted with this new list
	UpdatePoetServers(ctx context.Context, in *UpdatePoetServersRequest, opts ...grpc.CallOption) (*UpdatePoetServersResponse, error)
}

type smesherServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSmesherServiceClient(cc grpc.ClientConnInterface) SmesherServiceClient {
	return &smesherServiceClient{cc}
}

func (c *smesherServiceClient) IsSmeshing(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IsSmeshingResponse, error) {
	out := new(IsSmeshingResponse)
	err := c.cc.Invoke(ctx, SmesherService_IsSmeshing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) StartSmeshing(ctx context.Context, in *StartSmeshingRequest, opts ...grpc.CallOption) (*StartSmeshingResponse, error) {
	out := new(StartSmeshingResponse)
	err := c.cc.Invoke(ctx, SmesherService_StartSmeshing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) StopSmeshing(ctx context.Context, in *StopSmeshingRequest, opts ...grpc.CallOption) (*StopSmeshingResponse, error) {
	out := new(StopSmeshingResponse)
	err := c.cc.Invoke(ctx, SmesherService_StopSmeshing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) SmesherID(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SmesherIDResponse, error) {
	out := new(SmesherIDResponse)
	err := c.cc.Invoke(ctx, SmesherService_SmesherID_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) Coinbase(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*CoinbaseResponse, error) {
	out := new(CoinbaseResponse)
	err := c.cc.Invoke(ctx, SmesherService_Coinbase_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) SetCoinbase(ctx context.Context, in *SetCoinbaseRequest, opts ...grpc.CallOption) (*SetCoinbaseResponse, error) {
	out := new(SetCoinbaseResponse)
	err := c.cc.Invoke(ctx, SmesherService_SetCoinbase_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) MinGas(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*MinGasResponse, error) {
	out := new(MinGasResponse)
	err := c.cc.Invoke(ctx, SmesherService_MinGas_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) SetMinGas(ctx context.Context, in *SetMinGasRequest, opts ...grpc.CallOption) (*SetMinGasResponse, error) {
	out := new(SetMinGasResponse)
	err := c.cc.Invoke(ctx, SmesherService_SetMinGas_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) EstimatedRewards(ctx context.Context, in *EstimatedRewardsRequest, opts ...grpc.CallOption) (*EstimatedRewardsResponse, error) {
	out := new(EstimatedRewardsResponse)
	err := c.cc.Invoke(ctx, SmesherService_EstimatedRewards_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) PostSetupStatus(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*PostSetupStatusResponse, error) {
	out := new(PostSetupStatusResponse)
	err := c.cc.Invoke(ctx, SmesherService_PostSetupStatus_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) PostSetupStatusStream(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (SmesherService_PostSetupStatusStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &SmesherService_ServiceDesc.Streams[0], SmesherService_PostSetupStatusStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &smesherServicePostSetupStatusStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SmesherService_PostSetupStatusStreamClient interface {
	Recv() (*PostSetupStatusStreamResponse, error)
	grpc.ClientStream
}

type smesherServicePostSetupStatusStreamClient struct {
	grpc.ClientStream
}

func (x *smesherServicePostSetupStatusStreamClient) Recv() (*PostSetupStatusStreamResponse, error) {
	m := new(PostSetupStatusStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *smesherServiceClient) PostSetupProviders(ctx context.Context, in *PostSetupProvidersRequest, opts ...grpc.CallOption) (*PostSetupProvidersResponse, error) {
	out := new(PostSetupProvidersResponse)
	err := c.cc.Invoke(ctx, SmesherService_PostSetupProviders_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) PostConfig(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*PostConfigResponse, error) {
	out := new(PostConfigResponse)
	err := c.cc.Invoke(ctx, SmesherService_PostConfig_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *smesherServiceClient) UpdatePoetServers(ctx context.Context, in *UpdatePoetServersRequest, opts ...grpc.CallOption) (*UpdatePoetServersResponse, error) {
	out := new(UpdatePoetServersResponse)
	err := c.cc.Invoke(ctx, SmesherService_UpdatePoetServers_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SmesherServiceServer is the server API for SmesherService service.
// All implementations should embed UnimplementedSmesherServiceServer
// for forward compatibility
type SmesherServiceServer interface {
	// Returns true iff node is currently smeshing
	IsSmeshing(context.Context, *emptypb.Empty) (*IsSmeshingResponse, error)
	// Starts smeshing, after completing the post setup.
	// Changing of the post setup options (e.g., number of units), after initial setup, is supported.
	// Returns success if request is accepted by node , failure if it fails
	StartSmeshing(context.Context, *StartSmeshingRequest) (*StartSmeshingResponse, error)
	// Stops smeshing, or the preceding post setup session, and optionally attempt to
	// delete the post setup data files(s).
	// Returns success if request is accepted by node, failure if it fails
	StopSmeshing(context.Context, *StopSmeshingRequest) (*StopSmeshingResponse, error)
	// Get the current smesher id generated by the node
	SmesherID(context.Context, *emptypb.Empty) (*SmesherIDResponse, error)
	// Get the current coinbase
	Coinbase(context.Context, *emptypb.Empty) (*CoinbaseResponse, error)
	// Set the coinbase
	// Returns success if request succeeds, failure if it fails
	SetCoinbase(context.Context, *SetCoinbaseRequest) (*SetCoinbaseResponse, error)
	// Get the current min gas for including txs in blocks by this smesher
	MinGas(context.Context, *emptypb.Empty) (*MinGasResponse, error)
	// Set a min gas units for including txs in blocks by this smesher
	// Returns success if request succeeds, failure if it fails
	SetMinGas(context.Context, *SetMinGasRequest) (*SetMinGasResponse, error)
	// Estimate smeshing rewards over the next upcoming epoch
	EstimatedRewards(context.Context, *EstimatedRewardsRequest) (*EstimatedRewardsResponse, error)
	// Returns the Post setup status
	PostSetupStatus(context.Context, *emptypb.Empty) (*PostSetupStatusResponse, error)
	// Returns a stream of updates for the Post setup status
	PostSetupStatusStream(*emptypb.Empty, SmesherService_PostSetupStatusStreamServer) error
	// Returns a list of available Post setup providers
	PostSetupProviders(context.Context, *PostSetupProvidersRequest) (*PostSetupProvidersResponse, error)
	// Returns the Post protocol config
	PostConfig(context.Context, *emptypb.Empty) (*PostConfigResponse, error)
	// UpdatePoetServers updates poet servers
	// All existing PoET servers will be substituted with this new list
	UpdatePoetServers(context.Context, *UpdatePoetServersRequest) (*UpdatePoetServersResponse, error)
}

// UnimplementedSmesherServiceServer should be embedded to have forward compatible implementations.
type UnimplementedSmesherServiceServer struct {
}

func (UnimplementedSmesherServiceServer) IsSmeshing(context.Context, *emptypb.Empty) (*IsSmeshingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsSmeshing not implemented")
}
func (UnimplementedSmesherServiceServer) StartSmeshing(context.Context, *StartSmeshingRequest) (*StartSmeshingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartSmeshing not implemented")
}
func (UnimplementedSmesherServiceServer) StopSmeshing(context.Context, *StopSmeshingRequest) (*StopSmeshingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopSmeshing not implemented")
}
func (UnimplementedSmesherServiceServer) SmesherID(context.Context, *emptypb.Empty) (*SmesherIDResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SmesherID not implemented")
}
func (UnimplementedSmesherServiceServer) Coinbase(context.Context, *emptypb.Empty) (*CoinbaseResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Coinbase not implemented")
}
func (UnimplementedSmesherServiceServer) SetCoinbase(context.Context, *SetCoinbaseRequest) (*SetCoinbaseResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetCoinbase not implemented")
}
func (UnimplementedSmesherServiceServer) MinGas(context.Context, *emptypb.Empty) (*MinGasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MinGas not implemented")
}
func (UnimplementedSmesherServiceServer) SetMinGas(context.Context, *SetMinGasRequest) (*SetMinGasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetMinGas not implemented")
}
func (UnimplementedSmesherServiceServer) EstimatedRewards(context.Context, *EstimatedRewardsRequest) (*EstimatedRewardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EstimatedRewards not implemented")
}
func (UnimplementedSmesherServiceServer) PostSetupStatus(context.Context, *emptypb.Empty) (*PostSetupStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostSetupStatus not implemented")
}
func (UnimplementedSmesherServiceServer) PostSetupStatusStream(*emptypb.Empty, SmesherService_PostSetupStatusStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method PostSetupStatusStream not implemented")
}
func (UnimplementedSmesherServiceServer) PostSetupProviders(context.Context, *PostSetupProvidersRequest) (*PostSetupProvidersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostSetupProviders not implemented")
}
func (UnimplementedSmesherServiceServer) PostConfig(context.Context, *emptypb.Empty) (*PostConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostConfig not implemented")
}
func (UnimplementedSmesherServiceServer) UpdatePoetServers(context.Context, *UpdatePoetServersRequest) (*UpdatePoetServersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePoetServers not implemented")
}

// UnsafeSmesherServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SmesherServiceServer will
// result in compilation errors.
type UnsafeSmesherServiceServer interface {
	mustEmbedUnimplementedSmesherServiceServer()
}

func RegisterSmesherServiceServer(s grpc.ServiceRegistrar, srv SmesherServiceServer) {
	s.RegisterService(&SmesherService_ServiceDesc, srv)
}

func _SmesherService_IsSmeshing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).IsSmeshing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_IsSmeshing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).IsSmeshing(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_StartSmeshing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StartSmeshingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).StartSmeshing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_StartSmeshing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).StartSmeshing(ctx, req.(*StartSmeshingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_StopSmeshing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopSmeshingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).StopSmeshing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_StopSmeshing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).StopSmeshing(ctx, req.(*StopSmeshingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_SmesherID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).SmesherID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_SmesherID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).SmesherID(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_Coinbase_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).Coinbase(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_Coinbase_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).Coinbase(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_SetCoinbase_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetCoinbaseRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).SetCoinbase(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_SetCoinbase_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).SetCoinbase(ctx, req.(*SetCoinbaseRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_MinGas_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).MinGas(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_MinGas_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).MinGas(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_SetMinGas_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetMinGasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).SetMinGas(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_SetMinGas_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).SetMinGas(ctx, req.(*SetMinGasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_EstimatedRewards_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EstimatedRewardsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).EstimatedRewards(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_EstimatedRewards_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).EstimatedRewards(ctx, req.(*EstimatedRewardsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_PostSetupStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).PostSetupStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_PostSetupStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).PostSetupStatus(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_PostSetupStatusStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(emptypb.Empty)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SmesherServiceServer).PostSetupStatusStream(m, &smesherServicePostSetupStatusStreamServer{stream})
}

type SmesherService_PostSetupStatusStreamServer interface {
	Send(*PostSetupStatusStreamResponse) error
	grpc.ServerStream
}

type smesherServicePostSetupStatusStreamServer struct {
	grpc.ServerStream
}

func (x *smesherServicePostSetupStatusStreamServer) Send(m *PostSetupStatusStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _SmesherService_PostSetupProviders_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PostSetupProvidersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).PostSetupProviders(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_PostSetupProviders_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).PostSetupProviders(ctx, req.(*PostSetupProvidersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_PostConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).PostConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_PostConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).PostConfig(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _SmesherService_UpdatePoetServers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePoetServersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SmesherServiceServer).UpdatePoetServers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SmesherService_UpdatePoetServers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SmesherServiceServer).UpdatePoetServers(ctx, req.(*UpdatePoetServersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SmesherService_ServiceDesc is the grpc.ServiceDesc for SmesherService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SmesherService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "spacemesh.v1.SmesherService",
	HandlerType: (*SmesherServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsSmeshing",
			Handler:    _SmesherService_IsSmeshing_Handler,
		},
		{
			MethodName: "StartSmeshing",
			Handler:    _SmesherService_StartSmeshing_Handler,
		},
		{
			MethodName: "StopSmeshing",
			Handler:    _SmesherService_StopSmeshing_Handler,
		},
		{
			MethodName: "SmesherID",
			Handler:    _SmesherService_SmesherID_Handler,
		},
		{
			MethodName: "Coinbase",
			Handler:    _SmesherService_Coinbase_Handler,
		},
		{
			MethodName: "SetCoinbase",
			Handler:    _SmesherService_SetCoinbase_Handler,
		},
		{
			MethodName: "MinGas",
			Handler:    _SmesherService_MinGas_Handler,
		},
		{
			MethodName: "SetMinGas",
			Handler:    _SmesherService_SetMinGas_Handler,
		},
		{
			MethodName: "EstimatedRewards",
			Handler:    _SmesherService_EstimatedRewards_Handler,
		},
		{
			MethodName: "PostSetupStatus",
			Handler:    _SmesherService_PostSetupStatus_Handler,
		},
		{
			MethodName: "PostSetupProviders",
			Handler:    _SmesherService_PostSetupProviders_Handler,
		},
		{
			MethodName: "PostConfig",
			Handler:    _SmesherService_PostConfig_Handler,
		},
		{
			MethodName: "UpdatePoetServers",
			Handler:    _SmesherService_UpdatePoetServers_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "PostSetupStatusStream",
			Handler:       _SmesherService_PostSetupStatusStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "spacemesh/v1/smesher.proto",
}
