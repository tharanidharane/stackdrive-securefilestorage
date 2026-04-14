import { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { BarChart2, Upload, FolderOpen, Shield, Settings, ChevronLeft, ChevronRight, Zap } from 'lucide-react';
import './Sidebar.css';

const navItems = [
  { path: '/overview', label: 'Overview', icon: BarChart2 },
  { path: '/upload', label: 'Upload', icon: Upload },
  { path: '/history', label: 'File History', icon: FolderOpen },
  { path: '/security', label: 'Security', icon: Shield },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar({ collapsed, onToggle }) {
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__logo">
        <div className="sidebar__logo-icon">
          <Zap size={20} />
        </div>
        {!collapsed && <span className="sidebar__logo-text">StackDrive</span>}
      </div>

      <div className="sidebar__separator" />

      <nav className="sidebar__nav">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `sidebar__nav-item ${isActive ? 'sidebar__nav-item--active' : ''}`
            }
            title={collapsed ? item.label : undefined}
          >
            <item.icon size={20} className="sidebar__nav-icon" />
            {!collapsed && <span className="sidebar__nav-label">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar__bottom">
        <div className="sidebar__separator" />
        <button className="sidebar__toggle" onClick={onToggle}>
          {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
