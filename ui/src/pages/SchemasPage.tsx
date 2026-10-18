import React, { useState } from 'react';
import { FileCode2, Upload, CheckCircle2, ChevronRight, ChevronDown, Trash2, ArrowUpRight, ShieldCheck } from 'lucide-react';
import { PageShell } from './PageShell';

export interface EndpointSpec {
  pathPattern: string;
  methods: string[];
  allowedQueryParams: string[];
  requiredFields: string[];
  allowedFields: string[];
  summary?: string;
}

export interface SchemaItem {
  id: string;
  name: string;
  version: string;
  description: string;
  format: 'openapi3_json' | 'openapi3_yaml';
  endpoints: EndpointSpec[];
  createdAt: string;
}

const INITIAL_SCHEMAS: SchemaItem[] = [
  {
    id: 'petstore-api',
    name: 'Petstore Microservice',
    version: '3.0.0',
    description: 'RESTful API quản lý thú cưng theo chuẩn OpenAPI 3.0',
    format: 'openapi3_yaml',
    createdAt: new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString(),
    endpoints: [
      {
        pathPattern: '/api/v1/pets',
        methods: ['GET', 'POST'],
        allowedQueryParams: ['limit', 'page', 'status'],
        requiredFields: ['name', 'category'],
        allowedFields: ['name', 'category', 'tag', 'photo_url'],
        summary: 'Danh sách và tạo mới thú cưng',
      },
      {
        pathPattern: '/api/v1/pets/{id}',
        methods: ['GET', 'PUT', 'DELETE'],
        allowedQueryParams: [],
        requiredFields: ['name'],
        allowedFields: ['name', 'tag'],
        summary: 'Tra cứu, sửa và xóa thú cưng theo ID',
      },
    ],
  },
  {
    id: 'user-service-api',
    name: 'User Management Service',
    version: '1.2.0',
    description: 'Quản trị danh tính và thông tin hồ sơ người dùng',
    format: 'openapi3_json',
    createdAt: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString(),
    endpoints: [
      {
        pathPattern: '/api/v1/users',
        methods: ['GET', 'POST'],
        allowedQueryParams: ['role', 'active', 'dept'],
        requiredFields: ['email', 'password', 'full_name'],
        allowedFields: ['email', 'password', 'full_name', 'phone', 'department'],
        summary: 'Truy vấn và đăng ký tài khoản mới',
      },
      {
        pathPattern: '/api/v1/users/{id}/roles',
        methods: ['GET', 'PUT'],
        allowedQueryParams: [],
        requiredFields: ['roles'],
        allowedFields: ['roles', 'effective_from'],
        summary: 'Gán vai trò và phân quyền tài khoản',
      },
    ],
  },
];

export const SchemasPage: React.FC = () => {
  const [schemas, setSchemas] = useState<SchemaItem[]>(INITIAL_SCHEMAS);
  const [selectedSchema, setSelectedSchema] = useState<SchemaItem | null>(INITIAL_SCHEMAS[0]);
  const [expandedEndpoints, setExpandedEndpoints] = useState<Record<string, boolean>>({});
  const [isUploading, setIsUploading] = useState(false);
  const [newSchemaId, setNewSchemaId] = useState('');
  const [newSchemaSpec, setNewSchemaSpec] = useState('');
  const [attachedPolicyNotice, setAttachedPolicyNotice] = useState<string | null>(null);

  const toggleEndpoint = (path: string) => {
    setExpandedEndpoints((prev) => ({ ...prev, [path]: !prev[path] }));
  };

  const handleUploadSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSchemaId.trim() || !newSchemaSpec.trim()) return;

    const newSchema: SchemaItem = {
      id: newSchemaId.trim().toLowerCase(),
      name: newSchemaId.trim(),
      version: '1.0.0',
      description: 'Schema vừa được tải lên',
      format: newSchemaSpec.trim().startsWith('{') ? 'openapi3_json' : 'openapi3_yaml',
      createdAt: new Date().toISOString(),
      endpoints: [
        {
          pathPattern: '/api/v1/resource',
          methods: ['GET', 'POST'],
          allowedQueryParams: ['filter', 'sort'],
          requiredFields: ['id', 'name'],
          allowedFields: ['id', 'name', 'status'],
          summary: 'Endpoint mẫu được bóc tách từ spec',
        },
      ],
    };

    setSchemas((prev) => [newSchema, ...prev]);
    setSelectedSchema(newSchema);
    setIsUploading(false);
    setNewSchemaId('');
    setNewSchemaSpec('');
  };

  const handleDelete = (id: string) => {
    setSchemas((prev) => prev.filter((s) => s.id !== id));
    if (selectedSchema?.id === id) {
      setSelectedSchema(null);
    }
  };

  const handleAttachToPolicy = (schemaId: string) => {
    setAttachedPolicyNotice(`Đã gắn schema "${schemaId}" vào Policy thành công! Bundle sẽ tự động kích hoạt Positive Security Model.`);
    setTimeout(() => setAttachedPolicyNotice(null), 5000);
  };

  const getMethodBadgeClass = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
      case 'POST':
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
      case 'PUT':
      case 'PATCH':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'DELETE':
        return 'bg-rose-500/20 text-rose-400 border border-rose-500/40';
      default:
        return 'bg-zinc-500/20 text-zinc-300 border border-zinc-500/40';
    }
  };

  return (
    <PageShell active="schemas">
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white">API Schemas (OpenAPI)</h2>
          <p className="text-xs text-muted-foreground mt-1">Quản trị đặc tả OpenAPI, bóc tách endpoints và Positive Security Model (W21-F-01)</p>
        </div>
        {/* Top Actions & Notice */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <span className="text-sm font-semibold text-zinc-200">
              Positive Security Model: Tự động chặn 100% endpoint, method và body fields không khai báo
            </span>
          </div>
          <button
            onClick={() => setIsUploading((prev) => !prev)}
            className="px-3.5 py-1.5 text-xs font-bold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-md inline-flex items-center gap-1.5 transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            Tải lên OpenAPI Spec
          </button>
        </div>

        {attachedPolicyNotice && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{attachedPolicyNotice}</span>
          </div>
        )}

        {/* Upload Drawer/Form */}
        {isUploading && (
          <form onSubmit={handleUploadSubmit} className="p-4 bg-card border border-cyan-500/30 rounded-xl space-y-3 shadow-lg">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-cyan-400" />
              Nạp OpenAPI Specification mới (v3.0 / v3.1)
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">
                  Schema ID (Chữ thường, dấu gạch nối):
                </label>
                <input
                  type="text"
                  placeholder="ví dụ: payment-service-v2"
                  value={newSchemaId}
                  onChange={(e) => setNewSchemaId(e.target.value)}
                  className="w-full px-3 py-1.5 text-sm bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">
                Nội dung OpenAPI Spec (Dán nội dung JSON hoặc YAML):
              </label>
              <textarea
                rows={6}
                placeholder="openapi: 3.0.0&#10;info:&#10;  title: Service API&#10;  version: 1.0.0&#10;paths:&#10;  /users:&#10;    get:&#10;      summary: ..."
                value={newSchemaSpec}
                onChange={(e) => setNewSchemaSpec(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-cyan-500"
                required
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsUploading(false)}
                className="px-3 py-1.5 text-xs font-semibold rounded bg-muted hover:bg-muted/80 text-foreground"
              >
                Hủy
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-bold rounded bg-cyan-600 hover:bg-cyan-500 text-white"
              >
                Xác thực & Lưu trữ
              </button>
            </div>
          </form>
        )}

        {/* Main Content Layout: Schemas List (Left) and Endpoints Detail (Right) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Schemas List */}
          <div className="lg:col-span-1 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Schemas đã đăng ký ({schemas.length})
            </h3>
            <div className="space-y-2">
              {schemas.map((s) => {
                const isSelected = selectedSchema?.id === s.id;
                return (
                  <div
                    key={s.id}
                    onClick={() => setSelectedSchema(s)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-card border-cyan-500/50 shadow-md ring-1 ring-cyan-500/30'
                        : 'bg-card/60 border-border hover:bg-card hover:border-border/80'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-bold text-sm text-white">{s.name}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{s.id}</div>
                      </div>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground uppercase">
                        v{s.version}
                      </span>
                    </div>

                    <p className="text-xs text-zinc-400 mt-2 line-clamp-2">
                      {s.description}
                    </p>

                    <div className="flex items-center justify-between mt-3 pt-2 border-t border-border/50 text-[11px] text-muted-foreground">
                      <span>{s.endpoints.length} endpoints</span>
                      <span className="uppercase font-mono text-[10px]">{s.format.replace('openapi3_', '')}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Endpoints & Rules Viewer */}
          <div className="lg:col-span-2">
            {selectedSchema ? (
              <div className="bg-card border border-border rounded-xl p-5 space-y-4 shadow-sm">
                <div className="flex items-center justify-between pb-3 border-b border-border">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <FileCode2 className="w-5 h-5 text-cyan-400" />
                      {selectedSchema.name}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {selectedSchema.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleAttachToPolicy(selectedSchema.id)}
                      className="px-3 py-1.5 text-xs font-bold rounded-lg bg-emerald-600/20 text-emerald-300 hover:bg-emerald-600 hover:text-white border border-emerald-500/40 inline-flex items-center gap-1 transition-colors"
                      title="Gắn schema này vào Policy đang hoạt động"
                    >
                      <ArrowUpRight className="w-3.5 h-3.5" />
                      Gắn vào Policy
                    </button>
                    <button
                      onClick={() => handleDelete(selectedSchema.id)}
                      className="p-1.5 text-muted-foreground hover:text-rose-400 rounded hover:bg-rose-500/10 transition-colors"
                      title="Xóa schema"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Danh sách Endpoints ({selectedSchema.endpoints.length})
                  </h4>

                  <div className="space-y-2">
                    {selectedSchema.endpoints.map((ep) => {
                      const isExpanded = expandedEndpoints[ep.pathPattern];
                      return (
                        <div
                          key={ep.pathPattern}
                          className="border border-border/70 rounded-lg overflow-hidden bg-background/50"
                        >
                          <div
                            onClick={() => toggleEndpoint(ep.pathPattern)}
                            className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer hover:bg-muted/40 transition-colors"
                          >
                            <div className="flex items-center gap-2.5">
                              {isExpanded ? (
                                <ChevronDown className="w-4 h-4 text-muted-foreground" />
                              ) : (
                                <ChevronRight className="w-4 h-4 text-muted-foreground" />
                              )}
                              <div className="flex items-center gap-1.5">
                                {ep.methods.map((m) => (
                                  <span
                                    key={m}
                                    className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${getMethodBadgeClass(
                                      m
                                    )}`}
                                  >
                                    {m}
                                  </span>
                                ))}
                              </div>
                              <span className="font-mono text-xs font-semibold text-zinc-200">
                                {ep.pathPattern}
                              </span>
                            </div>

                            {ep.summary && (
                              <span className="text-xs text-muted-foreground hidden sm:inline">
                                {ep.summary}
                              </span>
                            )}
                          </div>

                          {/* Expanded Detail */}
                          {isExpanded && (
                            <div className="px-4 py-3 border-t border-border/60 bg-muted/20 text-xs space-y-2.5">
                              {/* Query parameters */}
                              <div>
                                <span className="font-semibold text-zinc-300">Tham số Query được phép: </span>
                                {ep.allowedQueryParams.length > 0 ? (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {ep.allowedQueryParams.map((q) => (
                                      <span
                                        key={q}
                                        className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                                      >
                                        ?{q}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground italic">Không có</span>
                                )}
                              </div>

                              {/* Required Fields */}
                              <div>
                                <span className="font-semibold text-zinc-300">Request Body Bắt buộc: </span>
                                {ep.requiredFields.length > 0 ? (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {ep.requiredFields.map((f) => (
                                      <span
                                        key={f}
                                        className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30"
                                      >
                                        *{f}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground italic">Không yêu cầu</span>
                                )}
                              </div>

                              {/* Allowed Fields */}
                              <div>
                                <span className="font-semibold text-zinc-300">Request Body Hợp lệ: </span>
                                {ep.allowedFields.length > 0 ? (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {ep.allowedFields.map((f) => (
                                      <span
                                        key={f}
                                        className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-zinc-300 border border-border"
                                      >
                                        {f}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground italic">Tất cả (nếu không siết chặt)</span>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center border border-dashed border-border rounded-xl text-muted-foreground">
                <FileCode2 className="w-10 h-10 mb-2 opacity-50" />
                <p className="text-sm">Chọn một schema từ danh sách để xem chi tiết endpoints</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </PageShell>
  );
};
