import React, { useState, useEffect } from 'react';
import {
  Users,
  UserPlus,
  Shield,
  CheckCircle2,
  XCircle,
  KeyRound,
  Trash2,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { fetchUsers, createUser, updateUser, deleteUser } from '../services/api';

const ROLE_OPTIONS = [
  { value: 'ADMIN_SOC', label: 'ADMIN_SOC — Administrador General SOC' },
  { value: 'ANALISTA_L2', label: 'ANALISTA_L2 — Analista Senior / Incident Responder N2' },
  { value: 'ANALISTA_L1', label: 'ANALISTA_L1 — Analista de Triaje N1' },
  { value: 'AUDITOR', label: 'AUDITOR — Auditor Forense / Compliance' }
];

export default function UsersManagementPanel({ currentUser, onNotify }) {
  const [users, setUsers] = useState([]);
  const [rolesCatalog, setRolesCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Form state for creating a new user in PostgreSQL
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('ANALISTA_L1');
  const [isCreating, setIsCreating] = useState(false);

  // Password reset state
  const [resetUserId, setResetUserId] = useState(null);
  const [newPassword, setNewPassword] = useState('');

  const isAdmin = currentUser?.role === 'ADMIN_SOC';

  const loadUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchUsers();
      setUsers(data.users || []);
      setRolesCatalog(data.roles_catalog || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setError('');
    setIsCreating(true);
    try {
      await createUser({
        email: email.trim(),
        full_name: fullName.trim(),
        password: password.trim(),
        role,
        is_active: true
      });
      setFullName('');
      setEmail('');
      setPassword('');
      setRole('ANALISTA_L1');
      if (onNotify) onNotify(`✅ Usuario "${email.trim()}" creado en PostgreSQL con rol ${role}`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsCreating(false);
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      await updateUser(userId, { role: newRole });
      if (onNotify) onNotify(`✅ Rol actualizado a ${newRole} en PostgreSQL`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (u) => {
    try {
      await updateUser(u.id, { is_active: !u.is_active });
      if (onNotify) {
        onNotify(`✅ Cuenta ${u.email} ${!u.is_active ? 'activada' : 'desactivada'} en PostgreSQL`);
      }
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleResetPassword = async (userId) => {
    if (!newPassword.trim() || newPassword.trim().length < 6) {
      setError('La nueva contraseña debe tener al menos 6 caracteres.');
      return;
    }
    try {
      await updateUser(userId, { password: newPassword.trim() });
      setResetUserId(null);
      setNewPassword('');
      if (onNotify) onNotify('✅ Contraseña actualizada con PBKDF2-SHA256 en PostgreSQL');
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDeleteUser = async (u) => {
    if (!window.confirm(`¿Eliminar permanentemente al usuario ${u.email} de PostgreSQL?`)) return;
    try {
      await deleteUser(u.id);
      if (onNotify) onNotify(`🗑️ Usuario ${u.email} eliminado de PostgreSQL`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Top Grid: Create User Form (if ADMIN_SOC) + RBAC Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Create User Card */}
        <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center gap-2.5 mb-4">
            <div className="p-2 rounded-xl bg-blue-500/15 text-blue-400 border border-blue-500/30">
              <UserPlus className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Crear Operador en PostgreSQL</h3>
              <p className="text-[11px] text-slate-400">
                Persistencia directa en tabla <code className="text-blue-400">soc_users</code>
              </p>
            </div>
          </div>

          {!isAdmin ? (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs">
              🔒 Tu rol actual (<strong>{currentUser?.role}</strong>) tiene acceso de lectura. Inicia sesión como{' '}
              <strong>ADMIN_SOC</strong> (<code className="font-mono">admin.soc@empresa.com</code>) para crear, modificar roles o eliminar usuarios en PostgreSQL.
            </div>
          ) : (
            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Nombre Completo</label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Ej. Carlos Mendoza"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Correo Institucional (Login)</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="cmendoza@empresa.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Contraseña Inicial (Mín. 6 caracteres)
                </label>
                <input
                  type="password"
                  required
                  minLength={6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Rol Operativo RBAC</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  {ROLE_OPTIONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="submit"
                disabled={isCreating}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold shadow-lg shadow-blue-500/20 transition-all cursor-pointer"
              >
                {isCreating ? 'Guardando en PostgreSQL...' : 'Guardar Nuevo Usuario en PostgreSQL'}
              </button>
            </form>
          )}
        </div>

        {/* RBAC Permissions Catalog */}
        <div className="lg:col-span-7 bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-purple-500/15 text-purple-400 border border-purple-500/30">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Matriz de Roles y Privilegios (RBAC)</h3>
                <p className="text-[11px] text-slate-400">
                  Políticas aplicadas en API Gateway y verificadas en cada petición JWT
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            {rolesCatalog.map((rc) => (
              <div key={rc.role} className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-blue-400">{rc.role}</span>
                  <span className="text-[11px] text-slate-300 font-semibold">{rc.label}</span>
                </div>
                <ul className="space-y-1 text-[11px] text-slate-400 pt-1">
                  {(rc.permissions || []).map((p, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <span className="text-emerald-400">✓</span>
                      <span>{p}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* PostgreSQL Users Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white">
              Usuarios Registrados en PostgreSQL (<code className="text-blue-400">soc_users</code>)
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-semibold">
              {users.length}
            </span>
          </div>
          <button
            onClick={loadUsers}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-semibold cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refrescar</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/50 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Nombre Completo</th>
                <th className="py-3 px-4">Correo (Login)</th>
                <th className="py-3 px-4">Rol Asignado</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Último Acceso</th>
                {isAdmin && <th className="py-3 px-4 text-right">Acciones Admin</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4 font-mono text-slate-400">#{u.id}</td>
                  <td className="py-3 px-4 font-semibold text-white">{u.full_name}</td>
                  <td className="py-3 px-4 font-mono text-blue-300">{u.email}</td>
                  <td className="py-3 px-4">
                    {isAdmin ? (
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-white"
                      >
                        <option value="ADMIN_SOC">ADMIN_SOC</option>
                        <option value="ANALISTA_L2">ANALISTA_L2</option>
                        <option value="ANALISTA_L1">ANALISTA_L1</option>
                        <option value="AUDITOR">AUDITOR</option>
                      </select>
                    ) : (
                      <span className="font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                        {u.role}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    {u.is_active ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px]">
                        <CheckCircle2 className="w-3 h-3" /> Activo
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[11px]">
                        <XCircle className="w-3 h-3" /> Inactivo
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {u.last_login ? new Date(u.last_login).toLocaleString() : 'Sin inicios aún'}
                  </td>
                  {isAdmin && (
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleToggleActive(u)}
                          className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] cursor-pointer"
                        >
                          {u.is_active ? 'Desactivar' : 'Activar'}
                        </button>
                        <button
                          onClick={() => setResetUserId(resetUserId === u.id ? null : u.id)}
                          className="p-1.5 rounded-lg bg-blue-500/15 hover:bg-blue-500/25 text-blue-300 cursor-pointer"
                          title="Cambiar Contraseña"
                        >
                          <KeyRound className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDeleteUser(u)}
                          className="p-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 cursor-pointer"
                          title="Eliminar Usuario"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      {resetUserId === u.id && (
                        <div className="mt-2 flex items-center justify-end gap-1.5">
                          <input
                            type="password"
                            placeholder="Nueva clave..."
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            className="bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-xs text-white w-36"
                          />
                          <button
                            onClick={() => handleResetPassword(u.id)}
                            className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold cursor-pointer"
                          >
                            Guardar
                          </button>
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
