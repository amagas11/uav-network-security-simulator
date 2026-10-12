<template>
  <div ref="chartRef" class="map-chart"></div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, ref, shallowRef } from "vue";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { clone as cloneSkeleton } from "three/examples/jsm/utils/SkeletonUtils.js";

const UAV_MODEL_URLS = [
  "/models/main.glb",
  "/models/DJI_大疆_Air_3S_无人机.glb",
  "/models/uav.glb",
];

const props = defineProps({
  attackPayload: {
    type: Object,
    default: null,
  },
  topologyLinks: {
    type: Array,
    default: () => [],
  },
});

const chartRef = ref(null);
let renderer = null;
let scene = null;
let camera = null;
let controls = null;
let animationFrameId = null;
let resizeObserver = null;
let desiredCameraPosition = null;
let desiredControlTarget = null;
let nodeGroup = null;
let baseEdgeGroup = null;
let transientEdgeGroup = null;
let persistentEdgeGroup = null;
let frameGroup = null;
const transientEdges = [];
const EDGE_FADE_MS = 7000;
let currentPhase = "normal";
let persistentDosSegment = null;
let sharedDroneModel = null;
let droneModelLoadPromise = null;

const nodes = shallowRef([]);
const links = shallowRef([]);
const nodeMap = shallowRef({});
const allNodes = shallowRef([]);
const allLinks = shallowRef([]);
let viewMode = "global";
const focusNodeSet = new Set();
const WORLD_BOUNDS = { x: 500, y: 420, z: 200 };
const WORLD_CENTER = { x: WORLD_BOUNDS.x / 2, y: WORLD_BOUNDS.y / 2, z: WORLD_BOUNDS.z / 2 };
const DEFAULT_CAMERA_POSITION = new THREE.Vector3(200, 200, 400);
const DEFAULT_CONTROL_TARGET = new THREE.Vector3(0, 0, 0);

const BASE_LINK_COLOR_BY_PHASE = {
  normal: "#64748B",
  attack: "#FB2C36",
  detect: "#F59E0B",
  defense: "#00BC7D",
  recover: "#22C55E",
};

const statusColor = {
  normal: "#cbd5e1",
  compromised: "#ef4444",
  attacker: "#f97316",
  victim: "#ef4444",
  dos_endpoint: "#fb923c",
  defended: "#22c55e",
};

function getNodeIconSizeByStatus(status) {
  if (status === "attacker" || status === "victim" || status === "dos_endpoint") {
    return 26;
  }
  if (status === "defended") {
    return 25;
  }
  return 50;
}

const directedEdgeStyle = {
  malicious: { color: "#ef4444", period: 1.25, symbolSize: 12, width: 4.4, opacity: 0.95, trailLength: 0.62 },
  traffic: { color: "#f97316", period: 1.35, symbolSize: 11, width: 4.2, opacity: 0.93, trailLength: 0.6 },
  passive: { color: "#94a3b8", period: 1.55, symbolSize: 10, width: 3.8, opacity: 0.92, trailLength: 0.58 },
  detect: { color: "#f59e0b", period: 0.9, symbolSize: 13, width: 4.8, opacity: 0.97, trailLength: 0.75 },
  defense: { color: "#22c55e", period: 1.0, symbolSize: 13, width: 4.8, opacity: 0.97, trailLength: 0.75 },
  blocked: { color: "#f59e0b", period: 0.95, symbolSize: 12, width: 4.6, opacity: 0.95, trailLength: 0.72 },
};

function toSceneVector(coord) {
  const [x, y, z] = coord;
  return new THREE.Vector3(
    x - WORLD_CENTER.x,
    z - WORLD_CENTER.z,
    y - WORLD_CENTER.y,
  );
}

function createLineMaterial(style) {
  return new THREE.LineBasicMaterial({
    color: style.color,
    transparent: true,
    opacity: style.opacity,
  });
}

function createLineObject(fromCoord, toCoord, style) {
  const points = [toSceneVector(fromCoord), toSceneVector(toCoord)];
  const geometry = new THREE.BufferGeometry().setFromPoints(points);
  const material = createLineMaterial(style);
  return new THREE.Line(geometry, material);
}

function createLabelSprite(text) {
  const canvas = document.createElement("canvas");
  canvas.width = 192;
  canvas.height = 64;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.fillStyle = "rgba(15, 23, 43, 0.84)";
  ctx.strokeStyle = "rgba(148, 163, 184, 0.9)";
  ctx.lineWidth = 2;
  ctx.roundRect(4, 4, 184, 56, 10);
  ctx.fill();
  ctx.stroke();
  ctx.fillStyle = "#ffffff";
  ctx.font = "22px sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, 96, 32);

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(40, 14, 1);
  return sprite;
}

function createFallbackDroneNode(status) {
  const color = statusColor[status] || statusColor.normal;
  const size = getNodeIconSizeByStatus(status);
  const scale = (size / 22) * 1.28;
  const drone = new THREE.Group();

  const bodyMaterial = new THREE.MeshStandardMaterial({ color, roughness: 0.35, metalness: 0.45 });
  const armMaterial = new THREE.MeshStandardMaterial({ color: "#cbd5e1", roughness: 0.45, metalness: 0.32 });
  const rotorMaterial = new THREE.MeshStandardMaterial({ color: "#334155", roughness: 0.72, metalness: 0.15 });

  const body = new THREE.Mesh(new THREE.SphereGeometry(2.7, 16, 16), bodyMaterial);
  drone.add(body);

  const armGeometry = new THREE.CylinderGeometry(0.42, 0.42, 10, 10);
  const rotorGeometry = new THREE.TorusGeometry(1.25, 0.22, 8, 20);
  const armOffsets = [
    [3.8, 0, 3.8],
    [3.8, 0, -3.8],
    [-3.8, 0, 3.8],
    [-3.8, 0, -3.8],
  ];

  armOffsets.forEach(([x, y, z]) => {
    const arm = new THREE.Mesh(armGeometry, armMaterial);
    arm.rotation.z = Math.PI / 2;
    arm.position.set(x / 2, y, z / 2);
    if (Math.sign(x) !== Math.sign(z)) {
      arm.rotation.y = Math.PI / 2;
    }
    drone.add(arm);

    const rotor = new THREE.Mesh(rotorGeometry, rotorMaterial);
    rotor.rotation.x = Math.PI / 2;
    rotor.position.set(x, 0.8, z);
    drone.add(rotor);
  });

  const tip = new THREE.Mesh(
    new THREE.ConeGeometry(0.9, 2.4, 12),
    new THREE.MeshStandardMaterial({ color: "#fdba74", roughness: 0.28, metalness: 0.5 }),
  );
  tip.position.set(0, 0.1, 3.9);
  tip.rotation.x = Math.PI / 2;
  drone.add(tip);

  drone.scale.setScalar(scale);
  return drone;
}

function tintModelByStatus(root, status) {
  const hex = statusColor[status] || statusColor.normal;
  const c = new THREE.Color(hex);
  const emissive = c.clone().multiplyScalar(0.18);
  root.traverse((obj) => {
    if (!obj.isMesh || !obj.geometry) return;
    const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
    const next = mats.map((m) => {
      const mat = m.clone();
      if ("emissive" in mat && mat.emissive) {
        if (status === "normal") {
          mat.emissiveIntensity = Math.min(mat.emissiveIntensity ?? 0, 0.08);
        } else {
          mat.emissive.copy(emissive);
          mat.emissiveIntensity = Math.max(mat.emissiveIntensity ?? 0, 0.22);
        }
      }
      return mat;
    });
    obj.material = next.length === 1 ? next[0] : next;
  });
}

function createStatusHalo(status) {
  const color = statusColor[status] || statusColor.normal;
  const halo = new THREE.Mesh(
    new THREE.TorusGeometry(2, 0.2, 12, 48),
    new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: status === "normal" ? 0.18 : 0.45,
    }),
  );
  halo.rotation.x = Math.PI / 2;
  halo.position.y = -2;
  return halo;
}

function createDroneNode(status) {
  if (sharedDroneModel) {
    const root = cloneSkeleton(sharedDroneModel);
    tintModelByStatus(root, status);
    const size = getNodeIconSizeByStatus(status);
    const scale = (size / 16) * 1.28;
    root.scale.multiplyScalar(scale);
    root.add(createStatusHalo(status));
    return root;
  }
  return createFallbackDroneNode(status);
}

function rebuildNodeMapFromNodes(list) {
  const m = {};
  for (const n of list) m[n.id] = [n.x, n.y, n.z];
  nodeMap.value = m;
}

function syncVisibleTopology() {
  if (viewMode === "focus" && focusNodeSet.size) {
    const filteredNodes = allNodes.value.filter((n) => focusNodeSet.has(n.id));
    if (!filteredNodes.length) {
      nodes.value = [...allNodes.value];
      links.value = [...allLinks.value];
      rebuildNodeMapFromNodes(nodes.value);
      return;
    }
    const idSet = new Set(filteredNodes.map((n) => n.id));
    nodes.value = filteredNodes;
    links.value = allLinks.value.filter((l) => idSet.has(String(l.source)) && idSet.has(String(l.target)));
    rebuildNodeMapFromNodes(nodes.value);
    return;
  }
  nodes.value = [...allNodes.value];
  links.value = [...allLinks.value];
  rebuildNodeMapFromNodes(nodes.value);
}

function moveCameraTo(position, target, instant = false) {
  if (!camera || !controls) return;
  if (instant) {
    camera.position.copy(position);
    controls.target.copy(target);
    controls.update();
    desiredCameraPosition = null;
    desiredControlTarget = null;
    return;
  }
  desiredCameraPosition = position.clone();
  desiredControlTarget = target.clone();
}

function fitCameraToVisibleNodes(instant = false) {
  if (!camera || !controls || !nodes.value.length) return;
  const box = new THREE.Box3();
  for (const node of nodes.value) {
    box.expandByPoint(toSceneVector([node.x, node.y, node.z]));
  }
  const center = box.getCenter(new THREE.Vector3());
  const size = box.getSize(new THREE.Vector3());
  const maxDim = Math.max(size.x, size.y, size.z, 20);
  const fovRad = THREE.MathUtils.degToRad(camera.fov);
  const fitDistance = (maxDim * 1.35) / (2 * Math.tan(fovRad / 2));
  const minDist = Math.max(controls.minDistance || 0, 70);
  const maxDist = controls.maxDistance || 1000;
  const finalDistance = Math.min(maxDist, Math.max(minDist, fitDistance * 1.2));
  const direction = new THREE.Vector3(1, 0.72, 1).normalize();
  const position = center.clone().add(direction.multiplyScalar(finalDistance));
  moveCameraTo(position, center, instant);
}

function resetCameraView(instant = false) {
  moveCameraTo(DEFAULT_CAMERA_POSITION, DEFAULT_CONTROL_TARGET, instant);
}

function toDisplayNodeId(rawId) {
  const n = Number(rawId);
  if (Number.isNaN(n)) return "";
  return String(n + 1);
}

function addFocusNode(nodeId) {
  const id = String(nodeId || "");
  if (!id) return;
  focusNodeSet.add(id);
}

function applyFocusFromPayload(payload) {
  focusNodeSet.clear();
  if (payload?.attack_src != null) addFocusNode(toDisplayNodeId(payload.attack_src));
  if (payload?.attack_dst != null) addFocusNode(toDisplayNodeId(payload.attack_dst));
  viewMode = focusNodeSet.size ? "focus" : "global";
  renderChart(currentPhase);
  if (viewMode === "focus") fitCameraToVisibleNodes(false);
}

function showGlobalTopology() {
  viewMode = "global";
  focusNodeSet.clear();
  renderChart(currentPhase);
  resetCameraView(false);
}

function createBaseLinkData(phase = "normal") {
  const color = BASE_LINK_COLOR_BY_PHASE[phase] || BASE_LINK_COLOR_BY_PHASE.normal;
  const width = phase === "normal" ? 1 : phase === "detect" || phase === "defense" ? 1.35 : 1.7;
  const opacity = phase === "normal" ? 0.28 : phase === "detect" || phase === "defense" ? 0.35 : phase === "recover" ? 0.32 : 0.45;
  const m = nodeMap.value;
  return links.value
    .map((l) => {
      const c0 = m[l.source];
      const c1 = m[l.target];
      if (!c0 || !c1) return null;
      return { coords: [c0, c1], lineStyle: { color, width, opacity } };
    })
    .filter(Boolean);
}

function disposeObject3D(root) {
  if (!root) return;
  root.traverse((obj) => {
    if (obj.geometry) obj.geometry.dispose();
    if (obj.material) {
      if (Array.isArray(obj.material)) {
        obj.material.forEach((m) => {
          if (m.map) m.map.dispose();
          m.dispose();
        });
      } else {
        if (obj.material.map) obj.material.map.dispose();
        obj.material.dispose();
      }
    }
  });
}

function clearGroup(group) {
  if (!group) return;
  while (group.children.length) {
    const child = group.children[group.children.length - 1];
    group.remove(child);
    disposeObject3D(child);
  }
}

function loadDroneModel() {
  if (droneModelLoadPromise) return droneModelLoadPromise;
  droneModelLoadPromise = new Promise((resolve) => {
    const loader = new GLTFLoader();
    const tryLoadByIndex = (index) => {
      if (index >= UAV_MODEL_URLS.length) {
        resolve(null);
        return;
      }
      loader.load(
        UAV_MODEL_URLS[index],
        (gltf) => {
          try {
            const model = gltf.scene;
            model.updateMatrixWorld(true);
            const box = new THREE.Box3().setFromObject(model);
            const center = box.getCenter(new THREE.Vector3());
            model.position.sub(center);
            model.updateMatrixWorld(true);
            const box2 = new THREE.Box3().setFromObject(model);
            const size = box2.getSize(new THREE.Vector3());
            const maxDim = Math.max(size.x, size.y, size.z, 1e-6);
            model.scale.multiplyScalar(16 / maxDim);
            if (!scene) {
              disposeObject3D(model);
              resolve(null);
              return;
            }
            sharedDroneModel = model;
            renderChart(currentPhase);
            resolve(model);
          } catch {
            resolve(null);
          }
        },
        undefined,
        () => {
          tryLoadByIndex(index + 1);
        },
      );
    };
    tryLoadByIndex(0);
  });
  return droneModelLoadPromise;
}

function rebuildNodes() {
  clearGroup(nodeGroup);
  nodes.value.forEach((node) => {
    const root = new THREE.Group();
    const drone = createDroneNode(node.status);
    root.add(drone);
    root.position.copy(toSceneVector([node.x, node.y, node.z]));

    const label = createLabelSprite(node.name);
    if (label) {
      label.position.set(0, 18, 0);
      root.add(label);
    }
    nodeGroup.add(root);
  });
}

function rebuildBaseLinks(phase = "normal") {
  clearGroup(baseEdgeGroup);
  const baseLinks = createBaseLinkData(phase);
  baseLinks.forEach((item) => {
    const line = createLineObject(item.coords[0], item.coords[1], item.lineStyle);
    baseEdgeGroup.add(line);
  });
}

function rebuildPersistentEdge() {
  clearGroup(persistentEdgeGroup);
  if (!persistentDosSegment) return;
  const line = createLineObject(persistentDosSegment[0], persistentDosSegment[1], {
    color: "#f97316",
    opacity: 0.95,
  });
  persistentEdgeGroup.add(line);
}

function addTransientEdgeObject(edge) {
  const line = createLineObject(edge.coords[0], edge.coords[1], {
    color: edge.baseStyle.color,
    opacity: edge.baseStyle.opacity,
  });
  const marker = new THREE.Mesh(
    new THREE.SphereGeometry(2.2, 12, 12),
    new THREE.MeshStandardMaterial({
      color: edge.baseStyle.color,
      emissive: edge.baseStyle.color,
      emissiveIntensity: 0.35,
      transparent: true,
      opacity: 1,
    }),
  );
  transientEdgeGroup.add(line);
  transientEdgeGroup.add(marker);
  edge.line = line;
  edge.marker = marker;
  edge.start = toSceneVector(edge.coords[0]);
  edge.end = toSceneVector(edge.coords[1]);
}

function defaultLayout() {
  const n = 12;
  const radius = 180;
  const arr = [];
  for (let i = 0; i < n; i += 1) {
    const angle = (Math.PI * 2 * i) / n;
    arr.push({
      id: String(i + 1),
      name: String(i + 1),
      x: 250 + radius * Math.cos(angle),
      y: 220 + radius * Math.sin(angle),
      z: 40 + (i % 4) * 20,
      status: "normal",
    });
  }
  const ring = arr.map((node, idx) => ({
    source: node.id,
    target: arr[(idx + 1) % arr.length].id,
    status: "active",
  }));
  allNodes.value = arr;
  allLinks.value = ring;
  syncVisibleTopology();
}

function applyTopologyFromServer(apiNodes, apiLinks = props.topologyLinks) {
  if (!Array.isArray(apiNodes) || apiNodes.length === 0) {
    defaultLayout();
    renderChart("normal");
    return;
  }

  const xs = apiNodes.map((n) => Number(n.pos?.[0] ?? 0));
  const ys = apiNodes.map((n) => Number(n.pos?.[1] ?? 0));
  const zs = apiNodes.map((n) => Number(n.pos?.[2] ?? 0));
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const minZ = Math.min(...zs);
  const maxZ = Math.max(...zs);
  const norm = (v, lo, hi, a, b) => (hi <= lo ? (a + b) / 2 : a + ((v - lo) / (hi - lo)) * (b - a));

  const arr = apiNodes.map((n) => ({
    id: String(Number(n.id) + 1),
    name: String(Number(n.id) + 1),
    x: norm(Number(n.pos?.[0] ?? 0), minX, maxX, 20, 480),
    y: norm(Number(n.pos?.[1] ?? 0), minY, maxY, 20, 420),
    z: norm(Number(n.pos?.[2] ?? 0), minZ, maxZ, 10, 190),
    status: "normal",
  }));

  const nodeIdSet = new Set(arr.map((n) => Number(n.id)));
  const normalizeEndpoint = (rawId) => {
    const n = Number(rawId);
    if (Number.isNaN(n)) return null;
    if (nodeIdSet.has(n + 1) && !nodeIdSet.has(n)) return String(n + 1);
    if (nodeIdSet.has(n)) return String(n);
    if (n >= 0 && n < arr.length) return String(n + 1);
    return null;
  };
  const isLinkActive = (rawStatus) => {
    if (rawStatus == null) return true;
    if (typeof rawStatus === "boolean") return rawStatus;
    if (typeof rawStatus === "number") return rawStatus !== 0 && rawStatus !== -1;
    const s = String(rawStatus).trim().toLowerCase();
    return !["inactive", "down", "blocked", "disable", "disabled", "0", "false"].includes(s);
  };
  const parseLinks = (onlyActive) => {
    const uniq = new Set();
    const result = [];
    for (const l of Array.isArray(apiLinks) ? apiLinks : []) {
      if (onlyActive && !isLinkActive(l?.status)) continue;
      const source = normalizeEndpoint(l?.src);
      const target = normalizeEndpoint(l?.dst);
      if (!source || !target || source === target) continue;
      const a = Number(source);
      const b = Number(target);
      const key = a < b ? `${a}-${b}` : `${b}-${a}`;
      if (uniq.has(key)) continue;
      uniq.add(key);
      result.push({ source, target, status: "active" });
    }
    return result;
  };

  let edgeList = [];
  if (Array.isArray(apiLinks) && apiLinks.length) {
    edgeList = parseLinks(true);
    if (!edgeList.length) edgeList = parseLinks(false);
  }
  if (!edgeList.length && !(Array.isArray(apiLinks) && apiLinks.length)) {
    const sorted = [...arr].sort((a, b) => Number(a.id) - Number(b.id));
    edgeList = sorted.map((n, idx) => ({ source: n.id, target: sorted[(idx + 1) % sorted.length].id, status: "active" }));
  }

  allNodes.value = arr;
  allLinks.value = edgeList;
  syncVisibleTopology();
  renderChart("normal");
}

function renderChart(phase = "normal") {
  if (!scene) return;
  currentPhase = phase || currentPhase;
  syncVisibleTopology();
  rebuildNodes();
  rebuildBaseLinks(currentPhase);
  rebuildPersistentEdge();
}

function initScene() {
  const container = chartRef.value;
  if (!container) return;
  scene = new THREE.Scene();

  camera = new THREE.PerspectiveCamera(48, 1, 0.1, 2000);
  camera.position.copy(DEFAULT_CAMERA_POSITION);
  camera.lookAt(DEFAULT_CONTROL_TARGET);

  renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  container.appendChild(renderer.domElement);

  controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.target.copy(DEFAULT_CONTROL_TARGET);
  controls.minDistance = 70;
  controls.maxDistance = 1000;
  controls.update();

  const ambient = new THREE.AmbientLight(0xffffff, 1);
  const key = new THREE.DirectionalLight(0xffffff, 1.05);
  key.position.set(240, 340, 120);
  const fill = new THREE.DirectionalLight(0x94a3b8, 0.35);
  fill.position.set(-220, 160, -150);
  scene.add(ambient, key, fill);

  const frameGeometry = new THREE.BoxGeometry(WORLD_BOUNDS.x, WORLD_BOUNDS.z, WORLD_BOUNDS.y);
  const edgesGeometry = new THREE.EdgesGeometry(frameGeometry);
  const frame = new THREE.LineSegments(
    edgesGeometry,
    new THREE.LineBasicMaterial({ color: "#475569", transparent: true, opacity: 0.42 }),
  );

  const floorGrid = new THREE.GridHelper(520, 20, 0x334155, 0x334155);
  floorGrid.position.y = -(WORLD_BOUNDS.z / 2);
  floorGrid.material.opacity = 0.28;
  floorGrid.material.transparent = true;

  frameGroup = new THREE.Group();
  frameGroup.add(frame, floorGrid);
  nodeGroup = new THREE.Group();
  baseEdgeGroup = new THREE.Group();
  transientEdgeGroup = new THREE.Group();
  persistentEdgeGroup = new THREE.Group();
  scene.add(frameGroup, baseEdgeGroup, persistentEdgeGroup, transientEdgeGroup, nodeGroup);

  resizeObserver = new ResizeObserver(() => resize());
  resizeObserver.observe(container);
}

function animate() {
  if (!renderer || !scene || !camera) return;
  if (desiredCameraPosition && desiredControlTarget && controls) {
    camera.position.lerp(desiredCameraPosition, 0.14);
    controls.target.lerp(desiredControlTarget, 0.16);
    if (
      camera.position.distanceTo(desiredCameraPosition) < 0.8 &&
      controls.target.distanceTo(desiredControlTarget) < 0.8
    ) {
      camera.position.copy(desiredCameraPosition);
      controls.target.copy(desiredControlTarget);
      desiredCameraPosition = null;
      desiredControlTarget = null;
    }
  }
  const now = Date.now();
  for (let i = transientEdges.length - 1; i >= 0; i -= 1) {
    const edge = transientEdges[i];
    if (edge.expireAt <= now) {
      if (edge.line) {
        transientEdgeGroup.remove(edge.line);
        disposeObject3D(edge.line);
      }
      if (edge.marker) {
        transientEdgeGroup.remove(edge.marker);
        disposeObject3D(edge.marker);
      }
      transientEdges.splice(i, 1);
      continue;
    }
    const lifeRatio = Math.max(0, (edge.expireAt - now) / EDGE_FADE_MS);
    const fade = 0.2 + 0.8 * lifeRatio;
    const progress = ((now - edge.createdAt) / (edge.baseStyle.period * 1000)) % 1;
    edge.marker.position.lerpVectors(edge.start, edge.end, progress);
    edge.line.material.opacity = edge.baseStyle.opacity * fade;
    edge.marker.material.opacity = fade;
    edge.marker.material.emissiveIntensity = 0.2 + 0.4 * fade;
  }

  controls?.update();
  renderer.render(scene, camera);
  animationFrameId = requestAnimationFrame(animate);
}

onMounted(() => {
  initScene();
  resetCameraView(true);
  defaultLayout();
  renderChart("normal");
  animate();
  loadDroneModel();
});

const resize = () => {
  if (!renderer || !camera || !chartRef.value) return;
  const { clientWidth, clientHeight } = chartRef.value;
  camera.aspect = clientWidth / Math.max(clientHeight, 1);
  camera.updateProjectionMatrix();
  renderer.setSize(clientWidth, clientHeight);
};

function changeNodeStatus(nodeId, status) {
  const id = String(nodeId);
  allNodes.value = allNodes.value.map((n) => (n.id === id ? { ...n, status } : n));
  renderChart(currentPhase);
}

function drawDirectedEdge(from, to, kind = "malicious") {
  const m = nodeMap.value;
  const source = m[String(from)];
  const target = m[String(to)];
  if (!source || !target || !scene) return;
  const edge = {
    coords: [source, target],
    kind,
    createdAt: Date.now(),
    expireAt: Date.now() + EDGE_FADE_MS,
    baseStyle: directedEdgeStyle[kind] || directedEdgeStyle.malicious,
  };
  transientEdges.push(edge);
  addTransientEdgeObject(edge);
}

function drawAttackEdge(from, to, success) {
  drawDirectedEdge(from, to, success ? "malicious" : "blocked");
}

function setPersistentDosSegment(nodeIdA, nodeIdB) {
  const m = nodeMap.value;
  const c0 = m[String(nodeIdA)];
  const c1 = m[String(nodeIdB)];
  if (!c0 || !c1 || !scene) return;
  persistentDosSegment = [c0, c1];
  renderChart(currentPhase);
}

function updateFlowByPhase(phase) {
  currentPhase = phase || "normal";
  renderChart(currentPhase);
}

function resetState() {
  for (let i = transientEdges.length - 1; i >= 0; i -= 1) {
    const edge = transientEdges[i];
    if (edge.line) {
      transientEdgeGroup.remove(edge.line);
      disposeObject3D(edge.line);
    }
    if (edge.marker) {
      transientEdgeGroup.remove(edge.marker);
      disposeObject3D(edge.marker);
    }
  }
  transientEdges.length = 0;
  persistentDosSegment = null;
  currentPhase = "normal";
  allNodes.value = allNodes.value.map((n) => ({ ...n, status: "normal" }));
  renderChart("normal");
}

function findLinkById(linkId) {
  const lid = Number(linkId);
  const list = props.topologyLinks || [];
  return list.find((l) => Number(l.id) === lid);
}

function applyEvent(event) {
  if (!event) return;
  const fromNode = String(event.fromNode || "");
  const toNode = String(event.toNode || "");
  const eventType = event.eventType;
  const payload = props.attackPayload;

  if (eventType === "attack") {
    if (!payload?.type) {
      if (fromNode) changeNodeStatus(fromNode, "victim");
      if (toNode) changeNodeStatus(toNode, "victim");
      if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "malicious");
      updateFlowByPhase("attack");
      return;
    }
    const atype = payload.type;
    if (atype === "Eavesdropping") {
      if (payload?.attack_src != null) changeNodeStatus(String(Number(payload.attack_src) + 1), "attacker");
      if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "passive");
      updateFlowByPhase("attack");
      return;
    }
    if (payload?.attack_src != null) changeNodeStatus(String(Number(payload.attack_src) + 1), "attacker");
    if (payload?.attack_dst != null) changeNodeStatus(String(Number(payload.attack_dst) + 1), "victim");
    if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "malicious");
    updateFlowByPhase("attack");
    return;
  }
  if (eventType === "detection") {
    if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "detect");
    updateFlowByPhase("detect");
    return;
  }
  if (eventType === "defense") {
    if (payload?.type === "Eavesdropping" && payload.attack_src != null) {
      const src = String(Number(payload.attack_src) + 1);
      changeNodeStatus(src, "defended");
      if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "defense");
    } else {
      if (fromNode) changeNodeStatus(fromNode, "defended");
      if (toNode) changeNodeStatus(toNode, "defended");
      if (fromNode && toNode) drawDirectedEdge(fromNode, toNode, "defense");
    }
    updateFlowByPhase("defense");
    return;
  }
  if (eventType === "recover") updateFlowByPhase("recover");
}

defineExpose({
  drawAttackEdge,
  drawDirectedEdge,
  changeNodeStatus,
  applyEvent,
  applyTopologyFromServer,
  resetState,
  applyFocusFromPayload,
  showGlobalTopology,
});

onBeforeUnmount(() => {
  if (animationFrameId) cancelAnimationFrame(animationFrameId);
  resizeObserver?.disconnect();
  resizeObserver = null;
  clearGroup(nodeGroup);
  clearGroup(baseEdgeGroup);
  clearGroup(transientEdgeGroup);
  clearGroup(persistentEdgeGroup);
  clearGroup(frameGroup);
  if (sharedDroneModel) {
    disposeObject3D(sharedDroneModel);
    sharedDroneModel = null;
  }
  droneModelLoadPromise = null;
  controls?.dispose();
  renderer?.dispose();
  if (chartRef.value && renderer?.domElement && chartRef.value.contains(renderer.domElement)) {
    chartRef.value.removeChild(renderer.domElement);
  }
  renderer = null;
  scene = null;
  camera = null;
  controls = null;
});
</script>

<style scoped>
.map-chart {
  width: 100%;
  height: 52vh;
  min-height: 40vh;
}
</style>
